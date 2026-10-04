package filecheck

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Limits of the reading of a document.
const (
	// maxLinks is the number of links kept per document.
	maxLinks = 50
	// maxInflated bounds the decompressed streams of a PDF, maxStreams
	// their number.
	maxInflated = 64 << 20
	maxStreams  = 2000
	// lureText is the most text a lure document holds: a sentence or two
	// around the link.
	lureText = 600
	// maxLureLinks is the most links a lure document holds.
	maxLureLinks = 3
)

// MessageLure starts the alert of a lure document, recognized by the risk
// assessment.
const MessageLure = "Document leurre"

// addLink records a link of the document, once.
func (r *Report) addLink(raw string) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") || len(r.Links) >= maxLinks {
		return
	}
	for _, l := range r.Links {
		if l == raw {
			return
		}
	}
	r.Links = append(r.Links, raw)
}

// readDocument extracts the links and measures the text of the documents
// whose content leads elsewhere: PDF, Office, OpenDocument, HTML and SVG.
// A document made of a short sentence and a link is a lure: it carries the
// phishing link past the mail filters, often through a legitimate sharing
// service.
func readDocument(r *Report, data []byte, depth int) {
	r.TextLength = -1
	switch r.family {
	case familyPDF:
		readPDF(r, data)
	case familyOOXML:
		readOOXML(r, data)
	case familyODF:
		readODF(r, data)
	case familyHTML, familySVG:
		readHTML(r, data, depth)
	default:
		return
	}
	if r.TextLength >= 0 && r.TextLength <= lureText && len(r.Links) > 0 && len(r.Links) <= maxLureLinks {
		r.Lure = true
		text := "presque aucun texte"
		if r.TextLength > 0 {
			text = fmt.Sprintf("%d caractères de texte", r.TextLength)
		}
		r.alert(LevelWarning, "%s : %s et %d lien%s (%s) ; ce genre de document sert à faire passer un lien d'hameçonnage "+
			"en contournant les filtres de la messagerie", MessageLure, text, len(r.Links), plural(len(r.Links)), strings.Join(r.Links, ", "))
	}
}

var (
	pdfStreamStart = regexp.MustCompile(`stream\r?\n`)
	pdfURI         = regexp.MustCompile(`/URI\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)`)
	pdfTextBlock   = regexp.MustCompile(`(?s)BT\b(.*?)\bET`)
	pdfLiteral     = regexp.MustCompile(`\((?:\\.|[^\\)])*\)`)
	pdfHex         = regexp.MustCompile(`<([0-9A-Fa-f\s]+)>`)
	pdfImageXObj   = regexp.MustCompile(`/Subtype\s*/Image\b`)
)

// readPDF reads the link annotations (/URI) and estimates the text drawn
// by the content streams, in the file and in its compressed streams
// (object streams included).
func readPDF(r *Report, data []byte) {
	parts := [][]byte{data}
	total := 0
	for i, loc := range pdfStreamStart.FindAllIndex(data, -1) {
		if i >= maxStreams || total >= maxInflated {
			break
		}
		zr, err := zlib.NewReader(bytes.NewReader(data[loc[1]:]))
		if err != nil {
			continue
		}
		inflated, _ := io.ReadAll(io.LimitReader(zr, int64(maxInflated-total)))
		total += len(inflated)
		if len(inflated) > 0 {
			parts = append(parts, inflated)
		}
	}
	text := 0
	names := map[string]bool{}
	for i, part := range parts {
		for _, m := range pdfURI.FindAllSubmatch(part, -1) {
			r.addLink(pdfString(m[1]))
		}
		// Only the decompressed content and object streams hold text and
		// objects: images and fonts are binary.
		if i == 0 || !textual(part) {
			continue
		}
		for _, m := range pdfName.FindAll(part, -1) {
			names[decodePDFName(string(m[1:]))] = true
		}
		for _, block := range pdfTextBlock.FindAllSubmatch(part, -1) {
			for _, s := range pdfLiteral.FindAll(block[1], -1) {
				text += len(strings.TrimSpace(pdfString(s)))
			}
			for _, h := range pdfHex.FindAllSubmatch(block[1], -1) {
				// Two bytes per glyph with the CID fonts of most generators.
				text += len(bytes.Join(bytes.Fields(h[1]), nil)) / 4
			}
		}
	}
	r.TextLength = text
	// The actions hidden in object streams escape inspectPDF.
	for _, k := range pdfKeywords {
		if !names[k.name] {
			continue
		}
		found := false
		for _, a := range r.Alerts {
			found = found || a.Message == k.message
		}
		if !found {
			r.alert(k.level, "%s", k.message)
		}
	}
}

// textual reports whether a stream is text (PDF operators and objects),
// not binary data.
func textual(data []byte) bool {
	sample := data[:min(len(data), 4096)]
	printable := 0
	for _, c := range sample {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return printable*10 >= len(sample)*9
}

// pdfString decodes a literal (...) or hexadecimal <...> PDF string.
func pdfString(s []byte) string {
	if len(s) < 2 {
		return ""
	}
	inner := s[1 : len(s)-1]
	if s[0] == '<' {
		var b []byte
		hex := bytes.Join(bytes.Fields(inner), nil)
		for i := 0; i+1 < len(hex); i += 2 {
			var v byte
			fmt.Sscanf(string(hex[i:i+2]), "%02x", &v)
			b = append(b, v)
		}
		return string(b)
	}
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c != '\\' || i+1 == len(inner) {
			b.WriteByte(c)
			continue
		}
		i++
		switch inner[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r', '\n':
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(inner[i])
		}
	}
	return b.String()
}

var xmlText = regexp.MustCompile(`<(?:w:t|a:t|t)(?:\s[^>]*)?>([^<]*)</(?:w:t|a:t|t)>`)

// readOOXML reads the external hyperlinks of the relationships and the text
// of the document, slides or shared strings.
func readOOXML(r *Report, data []byte) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	text := 0
	for _, f := range z.File {
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(name, ".rels"):
			var rels relationships
			if xml.Unmarshal([]byte(readPart(f)), &rels) != nil {
				continue
			}
			for _, rel := range rels.Relationships {
				if strings.EqualFold(rel.TargetMode, "External") && path.Base(rel.Type) == "hyperlink" {
					r.addLink(rel.Target)
				}
			}
		case name == "word/document.xml", strings.HasPrefix(name, "ppt/slides/slide") && strings.HasSuffix(name, ".xml"),
			name == "xl/sharedstrings.xml":
			part := readPart(f)
			for _, m := range xmlText.FindAllStringSubmatch(part, -1) {
				text += len(strings.TrimSpace(m[1]))
			}
			// HYPERLINK fields hold their target in the field code.
			for _, m := range fieldLink.FindAllStringSubmatch(part, -1) {
				r.addLink(m[1])
			}
		}
	}
	r.TextLength = text
}

var (
	fieldLink = regexp.MustCompile(`HYPERLINK\s+(?:&quot;|")([^"&]+)`)
	odfLink   = regexp.MustCompile(`xlink:href="([^"]+)"`)
	xmlTag    = regexp.MustCompile(`<[^>]*>`)
)

// readODF reads the links and the text of an OpenDocument file.
func readODF(r *Report, data []byte) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	for _, f := range z.File {
		if f.Name != "content.xml" {
			continue
		}
		content := readPart(f)
		for _, m := range odfLink.FindAllStringSubmatch(content, -1) {
			r.addLink(html.UnescapeString(m[1]))
		}
		r.TextLength = len(strings.Join(strings.Fields(html.UnescapeString(xmlTag.ReplaceAllString(content, " "))), " "))
	}
}

var (
	urlInScript  = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"'<>\\` + "`" + `]*)?`)
	dataDocument = regexp.MustCompile(`(?i)data:(application/(?:pdf|msword|vnd\.[a-z0-9.\-]+|octet-stream|zip|x-zip-compressed)|text/html);base64,([A-Za-z0-9+/=\s]+)`)
)

// readHTML reads the links of a web page (anchors, forms, frames, URLs
// written in its scripts) and its visible text, and analyzes the documents
// hidden inside it as data: URLs (a PDF shown by an <embed>).
func readHTML(r *Report, data []byte, depth int) {
	z := html.NewTokenizer(bytes.NewReader(data))
	text, skip := 0, 0
	for done := false; !done; {
		switch z.Next() {
		case html.ErrorToken:
			done = true
		case html.TextToken:
			if skip == 0 {
				text += len(strings.Join(strings.Fields(string(z.Text())), " "))
			} else {
				for _, u := range urlInScript.FindAllString(string(z.Text()), maxLinks) {
					r.addLink(u)
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := atom.Lookup(name)
			if tag == atom.Script || tag == atom.Style || tag == atom.Title {
				skip++
			}
			for hasAttr {
				var key, val []byte
				key, val, hasAttr = z.TagAttr()
				switch string(key) {
				case "href", "action", "src", "data", "formaction":
					r.addLink(string(val))
				case "content":
					if _, target, ok := strings.Cut(strings.ToLower(string(val)), "url="); ok {
						r.addLink(string(val)[len(val)-len(target):])
					}
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if tag := atom.Lookup(name); tag == atom.Script || tag == atom.Style || tag == atom.Title {
				skip = max(0, skip-1)
			}
		}
	}
	r.TextLength = text

	if depth > 0 {
		return
	}
	for _, m := range dataDocument.FindAllSubmatch(data, 5) {
		clean := strings.Join(strings.Fields(string(m[2])), "")
		inner, err := base64.StdEncoding.DecodeString(clean)
		if err != nil || len(inner) == 0 {
			continue
		}
		embedded := analyze("document intégré", string(m[1]), inner, depth+1)
		r.alert(LevelDanger, "Cache un document dans la page (%s, %d octets) : technique pour échapper à l'analyse des pièces jointes",
			embedded.Kind, len(inner))
		for _, a := range embedded.Alerts {
			if !strings.HasPrefix(a.Message, MessageLure) {
				r.alert(a.Level, "Document caché : %s", a.Message)
			}
		}
		for _, l := range embedded.Links {
			r.addLink(l)
		}
		// The page only shows the hidden document: its text is what the
		// reader sees.
		if embedded.TextLength >= 0 && text < lureText {
			r.TextLength = embedded.TextLength
		}
	}
}
