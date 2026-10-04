package main

import (
	"bytes"
	"fmt"
	"html"
	"net/url"
	"strings"

	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Remote images are blocked in the mail viewer (mailCSP), which browsers
// show as a broken image. They are replaced by a placeholder drawn in SVG,
// a data: URL the viewer allows: an image icon, the alternative text and
// the blocked host, in the size of the original image.

// maxPlaceholderText bounds the alternative text shown.
const maxPlaceholderText = 60

// placeholderImages rewrites the remote images of an HTML part. The rest of
// the document is copied byte for byte.
func placeholderImages(data []byte) []byte {
	z := nethtml.NewTokenizer(bytes.NewReader(data))
	var out bytes.Buffer
	out.Grow(len(data))
	for {
		tt := z.Next()
		if tt == nethtml.ErrorToken {
			return out.Bytes()
		}
		raw := z.Raw()
		if tt != nethtml.StartTagToken && tt != nethtml.SelfClosingTagToken {
			out.Write(raw)
			continue
		}
		// Raw is reused by the tokenizer: keep a copy before Token.
		raw = bytes.Clone(raw)
		token := z.Token()
		if token.DataAtom != atom.Img {
			out.Write(raw)
			continue
		}
		src, alt := "", ""
		for _, a := range token.Attr {
			switch a.Key {
			case "src":
				src = a.Val
			case "alt":
				alt = a.Val
			}
		}
		host := remoteHost(src)
		if host == "" {
			out.Write(raw)
			continue
		}
		attrs := token.Attr[:0]
		for _, a := range token.Attr {
			switch a.Key {
			case "src", "srcset", "title":
			default:
				attrs = append(attrs, a)
			}
		}
		token.Attr = append(attrs,
			nethtml.Attribute{Key: "src", Val: placeholderSVG(alt, host)},
			nethtml.Attribute{Key: "title", Val: "Image distante bloquée : " + src})
		out.WriteString(token.String())
	}
}

// remoteHost returns the host of a remote image URL, "" for the images of
// the mail (cid:, relative) and data: URLs.
func remoteHost(src string) string {
	src = cleanURL(src)
	lower := strings.ToLower(src)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "//") {
		return ""
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return "?"
	}
	return displayHost(strings.ToLower(u.Hostname()))
}

// placeholderSVG draws a placeholder filling the image box: a dashed frame,
// a picture icon and, when there is room, the alternative text and the
// host. The SVG has no size of its own, so that its percentages follow the
// width and height of the image; without them, the image takes the default
// size of a replaced element (300 x 150).
func placeholderSVG(alt, host string) string {
	alt = strings.Join(strings.Fields(alt), " ")
	if r := []rune(alt); len(r) > maxPlaceholderText {
		alt = string(r[:maxPlaceholderText-1]) + "…"
	}
	label := "Image bloquée"
	if alt != "" {
		label = alt
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg">`+
		`<rect x="1" y="1" width="99%%" height="98%%" rx="6" fill="#f3f5f8" stroke="#c4ccd6" stroke-dasharray="4 3"/>`+
		`<svg x="50%%" y="50%%" overflow="visible"><g transform="translate(-14 -30)" fill="none" stroke="#8a96a3" stroke-width="2" stroke-linejoin="round">`+
		`<rect x="1" y="1" width="26" height="20" rx="3"/><circle cx="9" cy="8" r="2.5"/><path d="m3 19 7-7 5 5 4-4 7 7"/></g>`+
		`<text y="8" text-anchor="middle" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="12" fill="#4a5562">%s</text>`+
		`<text y="24" text-anchor="middle" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="10" fill="#8a96a3">%s</text></svg></svg>`,
		html.EscapeString(label), html.EscapeString(host))
	return "data:image/svg+xml," + url.PathEscape(svg)
}
