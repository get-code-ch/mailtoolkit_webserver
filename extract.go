package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/get-code-ch/mailtoolkit"
)

// maxExtracted is the maximum number of mails extracted from a carrier.
const maxExtracted = 10

// Formats of an extracted mail.
const (
	formatEML = "eml"
	formatMSG = "msg"
)

// extractedMail is a mail attached to a carrier mail, kept byte for byte so
// that its signatures can be verified.
type extractedMail struct {
	Filename string
	Format   string
	Data     []byte
}

// extractMails returns the mails attached to carrier: message/rfc822 parts
// (inline or attached), .eml files and Outlook .msg files. A carrier that
// could only be partially parsed returns the mails found and the parse
// error.
func extractMails(carrier []byte) ([]extractedMail, error) {
	parsed, parseErr := mailtoolkit.Parse(carrier)

	var found []extractedMail
	add := func(info mailtoolkit.ContentInfo, decode func() ([]byte, error)) {
		if len(found) >= maxExtracted {
			return
		}
		name := info.Disposition.Parameters["filename"]
		if name == "" {
			name = info.Type.Parameters["name"]
		}
		format := mailFormat(info.Type, name)
		if format == "" {
			return
		}
		data, err := decode()
		if err != nil || len(data) == 0 {
			return
		}
		if name == "" {
			name = fmt.Sprintf("message-%d.%s", len(found)+1, format)
		}
		found = append(found, extractedMail{Filename: name, Format: format, Data: data})
	}

	for _, key := range contentKeys(parsed.Contents) {
		content := parsed.Contents[key]
		add(content.ContentInfo, content.Decode)
	}
	for _, name := range sortedKeys(parsed.Attachments) {
		attachment := parsed.Attachments[name]
		add(attachment.ContentInfo, attachment.Decode)
	}
	return found, parseErr
}

// mailFormat tells whether a part is a mail, from its type or file name.
func mailFormat(contentType mailtoolkit.ContentType, filename string) string {
	mediaType := contentType.Type + "/" + contentType.Subtype
	ext := strings.ToLower(path.Ext(filename))
	switch {
	case mediaType == "message/rfc822" || mediaType == "message/global" || ext == ".eml":
		return formatEML
	case mediaType == "application/vnd.ms-outlook" || ext == ".msg":
		return formatMSG
	}
	return ""
}
