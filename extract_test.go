package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// buildCarrier wraps parts (each one with its own headers) in a
// multipart/mixed carrier mail, as sent by "Forward as attachment".
func buildCarrier(parts ...string) []byte {
	var b strings.Builder
	b.WriteString("From: user@example.org\r\nTo: box@analyzer.test\r\nSubject: Fwd: suspect\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"carrier-b\"\r\n\r\n" +
		"--carrier-b\r\nContent-Type: text/plain\r\n\r\nPlease analyze the attached mail.\r\n")
	for _, part := range parts {
		b.WriteString("--carrier-b\r\n" + part + "\r\n")
	}
	b.WriteString("--carrier-b--\r\n")
	return []byte(b.String())
}

func wrapBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	return b.String()
}

func TestExtractMails(t *testing.T) {
	suspect := readTestdata(t, "multipartcomplex.eml")
	other := readTestdata(t, "alldest.eml")
	msg := []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fake outlook message")

	tests := []struct {
		name  string
		parts []string
		want  []extractedMail
	}{
		{
			name:  "message/rfc822 attachment",
			parts: []string{"Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"suspect.eml\"\r\n\r\n" + string(suspect)},
			want:  []extractedMail{{"suspect.eml", formatEML, suspect}},
		},
		{
			name:  "inline message/rfc822 without name",
			parts: []string{"Content-Type: message/rfc822\r\n\r\n" + string(suspect)},
			want:  []extractedMail{{"message-1.eml", formatEML, suspect}},
		},
		{
			name:  "base64 encoded message/rfc822",
			parts: []string{"Content-Type: message/rfc822; name=\"x.eml\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrapBase64(suspect)},
			want:  []extractedMail{{"x.eml", formatEML, suspect}},
		},
		{
			name:  ".eml file as octet-stream",
			parts: []string{"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"Suspect.EML\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrapBase64(suspect)},
			want:  []extractedMail{{"Suspect.EML", formatEML, suspect}},
		},
		{
			name:  "outlook .msg",
			parts: []string{"Content-Type: application/vnd.ms-outlook\r\nContent-Disposition: attachment; filename=\"suspect.msg\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrapBase64(msg)},
			want:  []extractedMail{{"suspect.msg", formatMSG, msg}},
		},
		{
			name: "two mails",
			parts: []string{
				"Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"b.eml\"\r\n\r\n" + string(other),
				"Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"a.eml\"\r\n\r\n" + string(suspect),
			},
			want: []extractedMail{{"a.eml", formatEML, suspect}, {"b.eml", formatEML, other}},
		},
		{
			name:  "no attached mail",
			parts: []string{"Content-Type: image/png\r\nContent-Disposition: attachment; filename=\"photo.png\"\r\n\r\nPNG"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractMails(buildCarrier(tt.parts...))
			if err != nil {
				t.Fatalf("extractMails: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("%d mails extracted, want %d", len(got), len(tt.want))
			}
			for i, want := range tt.want {
				if got[i].Filename != want.Filename || got[i].Format != want.Format {
					t.Errorf("mail %d = %s (%s), want %s (%s)", i, got[i].Filename, got[i].Format, want.Filename, want.Format)
				}
				if !bytes.Equal(got[i].Data, want.Data) {
					t.Errorf("mail %d is not byte for byte identical (%d bytes, want %d)", i, len(got[i].Data), len(want.Data))
				}
			}
		})
	}
}

func TestExtractMailsLimit(t *testing.T) {
	var parts []string
	for i := range maxExtracted + 2 {
		parts = append(parts, fmt.Sprintf("Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"%02d.eml\"\r\n\r\nSubject: %d\r\n\r\nbody\r\n", i, i))
	}
	got, err := extractMails(buildCarrier(parts...))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxExtracted {
		t.Errorf("%d mails extracted, want %d", len(got), maxExtracted)
	}
}

func TestExtractMailsNotMultipart(t *testing.T) {
	got, err := extractMails([]byte("From: user@example.org\r\nSubject: no attachment\r\n\r\nhello\r\n"))
	if err != nil || len(got) != 0 {
		t.Errorf("extractMails = %v, %v; want nothing", got, err)
	}
}
