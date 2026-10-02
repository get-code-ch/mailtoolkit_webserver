package msg

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"time"
)

// ConvertedHeader marks the mails converted from a .msg file.
const ConvertedHeader = "X-Converted-From"

// headersReplaced are rebuilt by the conversion: the body structure of the
// original mail is not kept in a .msg file.
var headersReplaced = map[string]bool{
	"content-type": true, "content-transfer-encoding": true, "mime-version": true,
	"content-disposition": true, strings.ToLower(ConvertedHeader): true,
}

// EML converts a message to an RFC 5322 mail. The original internet
// headers are kept when the .msg holds them; the body is rebuilt, so the
// DKIM signatures of the original mail no longer verify.
func (m *Message) EML() []byte {
	return m.eml(0)
}

func (m *Message) eml(depth int) []byte {
	var b bytes.Buffer
	if headers := strings.TrimSpace(m.TransportHeaders); headers != "" {
		if !writeOriginalHeaders(&b, headers) && !m.Date.IsZero() {
			fmt.Fprintf(&b, "Date: %s\r\n", m.Date.Format(time.RFC1123Z))
		}
	} else {
		m.writeHeaders(&b)
	}
	b.WriteString(ConvertedHeader + ": Outlook .msg\r\nMIME-Version: 1.0\r\n")

	boundary := newBoundary()
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)

	alternative := newBoundary()
	fmt.Fprintf(&b, "--%s\r\nContent-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary, alternative)
	if m.Body != "" || m.HTML == "" {
		fmt.Fprintf(&b, "--%s\r\n", alternative)
		writeBase64Part(&b, "text/plain; charset=utf-8", "", []byte(m.Body))
	}
	if m.HTML != "" {
		fmt.Fprintf(&b, "--%s\r\n", alternative)
		writeBase64Part(&b, "text/html; charset=utf-8", "", []byte(m.HTML))
	}
	fmt.Fprintf(&b, "--%s--\r\n", alternative)

	for _, a := range m.Attachments {
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		if a.Embedded != nil && depth < maxDepth {
			fmt.Fprintf(&b, "Content-Type: message/rfc822\r\nContent-Disposition: %s\r\n\r\n",
				mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))
			b.Write(a.Embedded.eml(depth + 1))
			b.WriteString("\r\n")
			continue
		}
		contentType := a.MIMEType
		if _, _, err := mime.ParseMediaType(contentType); err != nil || contentType == "" {
			contentType = "application/octet-stream"
		}
		disposition := "attachment"
		var extra string
		if a.ContentID != "" {
			// Inline images referenced by cid: in the HTML body.
			disposition = "inline"
			extra = "Content-ID: <" + strings.Trim(a.ContentID, "<>") + ">\r\n"
		}
		if params := map[string]string{"filename": a.Filename}; a.Filename != "" {
			extra += "Content-Disposition: " + mime.FormatMediaType(disposition, params) + "\r\n"
		} else {
			extra += "Content-Disposition: " + disposition + "\r\n"
		}
		writeBase64Part(&b, contentType, extra, a.Data)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// writeOriginalHeaders copies the transport headers, without the fields
// describing the original body structure, and reports whether they hold a
// Date field.
func writeOriginalHeaders(b *bytes.Buffer, headers string) (hasDate bool) {
	headers = strings.ReplaceAll(strings.ReplaceAll(headers, "\r\n", "\n"), "\n", "\r\n")
	keep := false
	for _, line := range strings.SplitAfter(headers, "\r\n") {
		if line == "" || line == "\r\n" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, _, _ := strings.Cut(line, ":")
			name = strings.ToLower(strings.TrimSpace(name))
			keep = !headersReplaced[name]
			hasDate = hasDate || name == "date"
		}
		if keep {
			b.WriteString(line)
			if !strings.HasSuffix(line, "\r\n") {
				b.WriteString("\r\n")
			}
		}
	}
	return hasDate
}

// writeHeaders builds the headers of a message without transport headers
// (a draft, or a message saved from the sent items).
func (m *Message) writeHeaders(b *bytes.Buffer) {
	address := func(name, email string) string {
		return (&mail.Address{Name: name, Address: email}).String()
	}
	if m.SenderEmail != "" || m.SenderName != "" {
		fmt.Fprintf(b, "From: %s\r\n", address(m.SenderName, m.SenderEmail))
	}
	for _, field := range []struct {
		name string
		typ  int
	}{{"To", RecipientTo}, {"Cc", RecipientCc}, {"Bcc", RecipientBcc}} {
		var list []string
		for _, r := range m.Recipients {
			if r.Type == field.typ || (field.typ == RecipientTo && r.Type == 0) {
				list = append(list, address(r.Name, r.Email))
			}
		}
		if len(list) > 0 {
			fmt.Fprintf(b, "%s: %s\r\n", field.name, strings.Join(list, ",\r\n "))
		}
	}
	if m.Subject != "" {
		fmt.Fprintf(b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	}
	if !m.Date.IsZero() {
		fmt.Fprintf(b, "Date: %s\r\n", m.Date.Format(time.RFC1123Z))
	}
	if m.MessageID != "" {
		fmt.Fprintf(b, "Message-ID: %s\r\n", m.MessageID)
	}
}

func writeBase64Part(b *bytes.Buffer, contentType, extraHeaders string, data []byte) {
	fmt.Fprintf(b, "Content-Type: %s\r\n%sContent-Transfer-Encoding: base64\r\n\r\n", contentType, extraHeaders)
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
}

func newBoundary() string {
	buf := make([]byte, 12)
	rand.Read(buf)
	return "msg-" + hex.EncodeToString(buf)
}
