package msg

import (
	"fmt"
	"testing"
)

// Example of [MS-OXRTFCP] §4.1.1: "{\rtf1\ansi\ansicpg1252\pard hello world}\r\n".
var specCompressed = []byte{
	0x2d, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x4c, 0x5a, 0x46, 0x75, 0xf1, 0xc5, 0xc7, 0xa7,
	0x03, 0x00, 0x0a, 0x00, 0x72, 0x63, 0x70, 0x67, 0x31, 0x32, 0x35, 0x42, 0x32, 0x0a, 0xf3, 0x20,
	0x68, 0x65, 0x6c, 0x09, 0x00, 0x20, 0x62, 0x77, 0x05, 0xb0, 0x6c, 0x64, 0x7d, 0x0a, 0x80, 0x0f,
	0xa0,
}

func TestDecompressRTF(t *testing.T) {
	got, err := DecompressRTF(specCompressed)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"; string(got) != want {
		t.Errorf("DecompressRTF = %q, want %q", got, want)
	}

	corrupted := append([]byte{}, specCompressed...)
	corrupted[20] ^= 0xFF
	if _, err := DecompressRTF(corrupted); err == nil {
		t.Error("corrupted data accepted (CRC not checked)")
	}

	uncompressed := append([]byte{0x15, 0, 0, 0, 0x0A, 0, 0, 0, 'M', 'E', 'L', 'A', 0, 0, 0, 0}, "{\\rtf1 x}"...)
	if got, err := DecompressRTF(uncompressed); err != nil || string(got) != "{\\rtf1 x}" {
		t.Errorf("MELA = %q, %v", got, err)
	}
	if _, err := DecompressRTF([]byte("short")); err == nil {
		t.Error("short data accepted")
	}
}

func TestHTMLFromRTF(t *testing.T) {
	rtf := `{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl{\f0\fswiss Arial;}}` + "\r\n" +
		`{\*\htmltag19 <html>}{\*\htmltag50 <body>}\htmlrtf {\f0 RTF only\par}\htmlrtf0 ` +
		`{\*\htmltag84 <p class="a">}Caf\'e9 \{ok\} \u8364?{\*\htmltag244 <a href="https://example.com/?a=1&amp;b=2">}lien{\*\htmltag252 </a>}` +
		`\htmlrtf\par\htmlrtf0{\*\htmltag92 </p>}{\*\htmltag58 </body></html>}}`
	html, ok := HTMLFromRTF([]byte(rtf))
	want := `<html><body><p class="a">Café {ok} €<a href="https://example.com/?a=1&amp;b=2">lien</a></p></body></html>`
	if !ok || html != want {
		t.Errorf("HTMLFromRTF =\n%q\nwant\n%q", html, want)
	}
	if _, ok := HTMLFromRTF([]byte(`{\rtf1\ansi plain RTF}`)); ok {
		t.Error("RTF without \\fromhtml1 reported as HTML")
	}
}

func TestControlWord(t *testing.T) {
	for input, want := range map[string]string{
		`\par next`:  "par 0 false 5",
		`\u-200?`:    "u -200 true 6",
		`\fs20\b`:    "fs 20 true 5",
		`\htmlrtf0x`: "htmlrtf 0 true 9",
		`\b-x`:       "b 0 false 2",
	} {
		word, param, hasParam, length := controlWord([]byte(input))
		got := fmt.Sprintf("%s %d %v %d", word, param, hasParam, length)
		if got != want {
			t.Errorf("controlWord(%q) = %s, want %s", input, got, want)
		}
	}
}
