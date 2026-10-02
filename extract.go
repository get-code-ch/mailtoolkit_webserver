package main

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/cfb"
	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
	"github.com/get-code-ch/mailtoolkit_webserver/msg"
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

// modeUpload is the envelope mode of the submissions uploaded on the site.
const modeUpload = "upload"

// errNotAMail is returned for an uploaded file which is neither an .eml
// nor an Outlook .msg file.
var errNotAMail = errors.New("the file is not a mail (.eml or .msg)")

// toEML returns a mail in the eml format, converting Outlook .msg files.
func toEML(format string, data []byte) ([]byte, error) {
	if format != formatMSG {
		return data, nil
	}
	m, err := msg.Read(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreadable, err)
	}
	return m.EML(), nil
}

// uploadedMail recognizes an uploaded mail from its content, whatever its
// name.
func uploadedMail(filename string, data []byte) (extractedMail, error) {
	if filename == "" {
		filename = "mail"
	}
	switch {
	case cfb.IsCFB(data):
		if !msg.IsMsg(data) {
			return extractedMail{}, errNotAMail
		}
		return extractedMail{Filename: filename, Format: formatMSG, Data: data}, nil
	case looksLikeMail(data):
		return extractedMail{Filename: filename, Format: formatEML, Data: data}, nil
	}
	return extractedMail{}, errNotAMail
}

// looksLikeMail checks that data starts with mail header fields.
func looksLikeMail(data []byte) bool {
	m := mailauth.ParseMessage(data[:min(len(data), 64<<10)])
	known := 0
	for _, f := range m.Fields {
		switch strings.ToLower(f.Name) {
		case "from", "to", "subject", "date", "received", "message-id", "return-path", "mime-version":
			known++
		}
	}
	return known >= 2
}
