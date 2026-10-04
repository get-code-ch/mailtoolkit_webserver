package filecheck

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func deflate(s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// pdfDocument builds a PDF with a content stream drawing text and a link
// annotation, compressed in an object stream when hidden is set.
func pdfDocument(text, link string, hidden bool) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	content := deflate(fmt.Sprintf("BT /F1 12 Tf 72 712 Td (%s) Tj ET", text))
	fmt.Fprintf(&b, "4 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(content))
	b.Write(content)
	b.WriteString("\nendstream\nendobj\n")
	annot := fmt.Sprintf("<< /Type /Annot /Subtype /Link /A << /S /URI /URI (%s) >> >>", link)
	if hidden {
		objects := deflate("5 0 " + annot + " << /S /JavaScript /JS (app.alert(1)) >>")
		fmt.Fprintf(&b, "6 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length %d /Filter /FlateDecode >>\nstream\n", len(objects))
		b.Write(objects)
		b.WriteString("\nendstream\nendobj\n")
	} else {
		b.WriteString("5 0 obj\n" + annot + "\nendobj\n")
	}
	b.WriteString("trailer\n<< /Root 1 0 R >>\n%%EOF\n")
	return b.Bytes()
}

func docx(text string, links ...string) []byte {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	add := func(name, content string) {
		f, _ := z.Create(name)
		f.Write([]byte(content))
	}
	add("[Content_Types].xml", `<Types/>`)
	add("word/document.xml", `<w:document><w:body><w:p><w:r><w:t xml:space="preserve">`+text+`</w:t></w:r></w:p></w:body></w:document>`)
	var rels strings.Builder
	rels.WriteString(`<Relationships>`)
	for i, l := range links {
		fmt.Fprintf(&rels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="%s" TargetMode="External"/>`, i, l)
	}
	rels.WriteString(`<Relationship Id="rS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`)
	add("word/_rels/document.xml.rels", rels.String())
	z.Close()
	return b.Bytes()
}

const share = "https://contoso-my.sharepoint.com/:b:/g/personal/x/EaBc?e=1"

func TestLureDocuments(t *testing.T) {
	long := strings.Repeat("Le présent contrat fixe les conditions de livraison. ", 30)
	tests := []struct {
		name  string
		file  string
		data  []byte
		lure  bool
		links []string
		alert string
	}{
		{"short PDF", "Facture.pdf", pdfDocument("Un document vous a ete partage. Cliquez pour le consulter.", share, false), true, []string{share}, MessageLure},
		{"long PDF", "Contrat.pdf", pdfDocument(long, share, false), false, []string{share}, ""},
		{"hidden in object stream", "Doc.pdf", pdfDocument("Voir le document", "https://evil.example/x", true), true,
			[]string{"https://evil.example/x"}, "Contient du JavaScript"},
		{"short DOCX", "Offre.docx", docx("Veuillez consulter l'offre sécurisée", share), true, []string{share}, MessageLure},
		{"DOCX without link", "Note.docx", docx("Bonjour"), false, nil, ""},
		{"HTML with hidden PDF", "Shipping.html", []byte(`<html><head><title>PDF Viewer</title></head><body><embed src="data:application/pdf;base64,` +
			base64.StdEncoding.EncodeToString(pdfDocument("Track your parcel", "https://a1b2c3d4e5f6g7.workers.dev/p", false)) +
			`" type="application/pdf"></body></html>`), true, []string{"https://a1b2c3d4e5f6g7.workers.dev/p"}, "Cache un document dans la page"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Analyze(tt.file, "", tt.data)
			if r.Lure != tt.lure || strings.Join(r.Links, " ") != strings.Join(tt.links, " ") {
				t.Errorf("lure %v, links %v, text %d", r.Lure, r.Links, r.TextLength)
			}
			found := tt.alert == ""
			for _, a := range r.Alerts {
				found = found || strings.HasPrefix(a.Message, tt.alert)
			}
			if !found {
				t.Errorf("no alert %q: %+v", tt.alert, r.Alerts)
			}
		})
	}
}

func TestPDFString(t *testing.T) {
	for in, want := range map[string]string{`(https://a.example/\(x\))`: "https://a.example/(x)", `<68747470733A2F2F622E6578>`: "https://b.ex", `(a\nb)`: "a\nb"} {
		if got := pdfString([]byte(in)); got != want {
			t.Errorf("%s: %q", in, got)
		}
	}
}
