package msg

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/internal/testcfb"
)

func unicode(id string, s string) testcfb.Node {
	var data []byte
	for _, u := range utf16.Encode([]rune(s + "\x00")) {
		data = binary.LittleEndian.AppendUint16(data, u)
	}
	return testcfb.Stream("__substg1.0_"+id+"001F", data)
}

// properties builds a __properties_version1.0 stream: header then 16 byte
// entries (tag, flags, value).
func properties(headerSize int, props map[uint32]uint64) testcfb.Node {
	data := make([]byte, headerSize)
	for tag, value := range props {
		entry := make([]byte, 16)
		binary.LittleEndian.PutUint32(entry, tag)
		binary.LittleEndian.PutUint64(entry[8:], value)
		data = append(data, entry...)
	}
	return testcfb.Stream("__properties_version1.0", data)
}

// filetime converts a time to a FILETIME.
func filetime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

const transportHeaders = "Received: from mail.sender.example (mail.sender.example [203.0.113.10])\r\n" +
	"\tby mx.recipient.example with ESMTPS id 1; Mon, 1 Oct 2018 10:00:01 +0000\r\n" +
	"DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=s1; h=from:subject; bh=x; b=y\r\n" +
	"From: Alice <alice@sender.example>\r\n" +
	"To: bob@recipient.example\r\n" +
	"Subject: Original subject\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/alternative;\r\n\tboundary=\"original\"\r\n" +
	"Message-ID: <1@sender.example>\r\n"

func buildMsg(withTransportHeaders bool) []byte {
	sent := time.Date(2018, 10, 1, 10, 0, 0, 0, time.UTC)
	root := []testcfb.Node{
		properties(32, map[uint32]uint64{
			0x0E060040: filetime(sent),
			0x3FFD0003: 1252,
		}),
		unicode("001A", "IPM.Note"),
		unicode("0037", "Réunion de lundi"),
		unicode("0C1A", "Alice"),
		unicode("5D01", "alice@sender.example"),
		unicode("1035", "<1@sender.example>"),
		testcfb.Stream("__substg1.0_1000001E", []byte("Texte en windows-1252 : caf\xe9 \x80\x00")),
		testcfb.Stream("__substg1.0_10130102", []byte("<p>caf\xe9 <img src=\"cid:logo@x\"> <a href=\"https://evil.example/\">lien</a></p>\x00\x00")),
		testcfb.Storage("__recip_version1.0_#00000000",
			properties(8, map[uint32]uint64{0x0C150003: 1}),
			unicode("3001", "Bob"), unicode("39FE", "bob@recipient.example")),
		testcfb.Storage("__recip_version1.0_#00000001",
			properties(8, map[uint32]uint64{0x0C150003: 2}),
			unicode("3001", "Carol"), unicode("3003", "carol@recipient.example")),
		testcfb.Storage("__attach_version1.0_#00000000",
			properties(8, map[uint32]uint64{0x37050003: 1}),
			unicode("3707", "rapport.pdf"), unicode("370E", "application/pdf"),
			testcfb.Stream("__substg1.0_37010102", []byte("%PDF-1.4 content"))),
		testcfb.Storage("__attach_version1.0_#00000001",
			properties(8, map[uint32]uint64{0x37050003: 1}),
			unicode("3707", "logo.png"), unicode("370E", "image/png"), unicode("3712", "logo@x"),
			testcfb.Stream("__substg1.0_37010102", []byte("\x89PNG\r\n\x1a\n"))),
		testcfb.Storage("__attach_version1.0_#00000002",
			properties(8, map[uint32]uint64{0x37050003: 5}),
			unicode("3707", "transfert.msg"),
			testcfb.Storage("__substg1.0_3701000D",
				properties(24, map[uint32]uint64{0x0E060040: filetime(sent.Add(-time.Hour))}),
				unicode("0037", "Message joint"),
				unicode("0C1F", "dave@other.example"),
				unicode("1000", "Corps du message joint"))),
	}
	if withTransportHeaders {
		root = append(root, unicode("007D", transportHeaders))
	}
	return testcfb.Build(root...)
}

func TestRead(t *testing.T) {
	data := buildMsg(true)
	if !IsMsg(data) || IsMsg(testcfb.Build(testcfb.Stream("WordDocument", []byte("w")))) || IsMsg([]byte("not a file")) {
		t.Error("IsMsg")
	}
	m, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Class != "IPM.Note" || m.Subject != "Réunion de lundi" || m.SenderName != "Alice" || m.SenderEmail != "alice@sender.example" ||
		m.MessageID != "<1@sender.example>" || !m.Date.Equal(time.Date(2018, 10, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("message = %+v", m)
	}
	if m.Body != "Texte en windows-1252 : café €" {
		t.Errorf("body = %q", m.Body)
	}
	if !strings.HasPrefix(m.HTML, "<p>café") || strings.HasSuffix(m.HTML, "\x00") || m.HTMLFromRTF {
		t.Errorf("html = %q", m.HTML)
	}
	if len(m.Recipients) != 2 || m.Recipients[0] != (Recipient{"Bob", "bob@recipient.example", RecipientTo}) ||
		m.Recipients[1] != (Recipient{"Carol", "carol@recipient.example", RecipientCc}) {
		t.Errorf("recipients = %+v", m.Recipients)
	}
	if len(m.Attachments) != 3 {
		t.Fatalf("%d attachments", len(m.Attachments))
	}
	if a := m.Attachments[0]; a.Filename != "rapport.pdf" || a.MIMEType != "application/pdf" || string(a.Data) != "%PDF-1.4 content" {
		t.Errorf("attachment 0 = %+v", a)
	}
	if a := m.Attachments[1]; a.ContentID != "logo@x" {
		t.Errorf("attachment 1 = %+v", a)
	}
	embedded := m.Attachments[2].Embedded
	if embedded == nil || embedded.Subject != "Message joint" || embedded.SenderEmail != "dave@other.example" ||
		embedded.Body != "Corps du message joint" || embedded.Date.IsZero() {
		t.Errorf("embedded = %+v", embedded)
	}

	if _, err := Read(testcfb.Build(testcfb.Stream("WordDocument", []byte("w")))); err == nil {
		t.Error("Word document read as a message")
	}
}

func TestEMLWithTransportHeaders(t *testing.T) {
	m, err := Read(buildMsg(true))
	if err != nil {
		t.Fatal(err)
	}
	eml := m.EML()
	mail, err := mailtoolkit.Parse(eml)
	if err != nil {
		t.Fatalf("converted mail does not parse: %v\n%s", err, eml)
	}
	h := mail.Header
	// The original headers are kept, the original MIME structure replaced.
	// The transport headers have no Date: the delivery time is added.
	if h.Date != "Mon, 01 Oct 2018 10:00:00 +0000" {
		t.Errorf("Date = %q", h.Date)
	}
	if h.Subject != "Original subject" || h.From != "alice@sender.example" || h.Elements["dkim-signature"] == "" ||
		!strings.Contains(h.Elements["received"], "203.0.113.10") || h.Elements["x-converted-from"] != "Outlook .msg" {
		t.Errorf("headers = %+v", h.Elements)
	}
	if strings.Contains(string(eml), "original\"") || strings.Count(string(eml), "MIME-Version") != 2 {
		t.Errorf("original Content-Type kept or MIME-Version duplicated:\n%.600s", eml)
	}

	var text, html string
	for _, c := range mail.Contents {
		data, _ := c.Decode()
		switch c.ContentInfo.Type.Subtype {
		case "plain":
			text = string(data)
		case "html":
			html = string(data)
		}
	}
	if text != "Texte en windows-1252 : café €" || !strings.Contains(html, `<a href="https://evil.example/">`) {
		t.Errorf("text %q, html %q", text, html)
	}
	if logo, ok := mail.Contents["logo@x"]; !ok || logo.ContentInfo.Type.Subtype != "png" {
		t.Errorf("inline image not reachable by Content-ID: %v", mail.Contents)
	}
	report, ok := mail.Attachments["rapport.pdf"]
	if data, _ := report.Decode(); !ok || string(data) != "%PDF-1.4 content" {
		t.Errorf("attachment = %q", data)
	}
	forwarded, ok := mail.Attachments["transfert.msg"]
	if !ok || forwarded.ContentInfo.Type.Type != "message" {
		t.Fatalf("embedded message not converted: %v", mail.Attachments)
	}
	inner, err := mailtoolkit.Parse(forwarded.Data)
	if err != nil || inner.Header.Subject != "Message joint" || inner.Header.From != "dave@other.example" {
		t.Errorf("embedded message = %+v, %v", inner.Header, err)
	}
}

func TestEMLWithoutTransportHeaders(t *testing.T) {
	m, err := Read(buildMsg(false))
	if err != nil {
		t.Fatal(err)
	}
	mail, err := mailtoolkit.Parse(m.EML())
	if err != nil {
		t.Fatal(err)
	}
	h := mail.Header
	if h.Subject != "Réunion de lundi" || h.From != "alice@sender.example" || h.To != "bob@recipient.example" ||
		h.Cc != "carol@recipient.example" || h.Date != "Mon, 01 Oct 2018 10:00:00 +0000" || h.Elements["message-id"] != "<1@sender.example>" {
		t.Errorf("synthesized headers = %+v", h)
	}
}
