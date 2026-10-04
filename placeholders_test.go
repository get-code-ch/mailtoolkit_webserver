package main

import (
	"html"
	"net/url"
	"strings"
	"testing"
)

func TestPlaceholderImages(t *testing.T) {
	in := `<p>Bonjour é</p><img src="https://cdn.example.com/logo.png" alt="Logo <DHL>" width="576" height="66" style="display:block" srcset="a.png 2x">` +
		`<img src=cid:x><IMG SRC='data:image/png;base64,AA'><img src="//t.example/p.gif" width=1 height=1/><br>`
	out := string(placeholderImages([]byte(in)))
	if !strings.HasPrefix(out, `<p>Bonjour é</p><img alt="Logo &lt;DHL&gt;" width="576" height="66" style="display:block" src="data:image/svg+xml,`) {
		t.Errorf("%s", out)
	}
	if strings.Contains(out, `src="https://`) || strings.Contains(out, "srcset") {
		t.Error("remote source kept")
	}
	if !strings.HasSuffix(out, `<img src=cid:x><IMG SRC='data:image/png;base64,AA'>`+out[strings.LastIndex(out, "<img"):]) ||
		!strings.Contains(out, `title="Image distante bloquée : //t.example/p.gif"`) || !strings.HasSuffix(out, "<br>") {
		t.Errorf("%s", out)
	}
	start := strings.Index(out, "data:image/svg+xml,") + len("data:image/svg+xml,")
	svg, err := url.PathUnescape(html.UnescapeString(out[start : strings.Index(out[start:], `"`)+start]))
	if err != nil || !strings.Contains(svg, "Logo &lt;DHL&gt;") || !strings.Contains(svg, "cdn.example.com") || strings.Contains(svg, "<DHL>") {
		t.Errorf("%v %s", err, svg)
	}
}
