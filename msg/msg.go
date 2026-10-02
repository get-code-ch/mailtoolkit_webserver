// Package msg reads Outlook .msg files ([MS-OXMSG]) and converts them to
// RFC 5322 mails, so that they go through the same analysis as .eml files.
package msg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/get-code-ch/mailtoolkit_webserver/cfb"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
)

// maxDepth bounds the embedded messages (a message attached to a message...).
const maxDepth = 5

// MAPI property ids.
const (
	propSubject               = 0x0037
	propMessageClass          = 0x001A
	propClientSubmitTime      = 0x0039
	propSentRepresentingName  = 0x0042
	propSentRepresentingEmail = 0x0065
	propTransportHeaders      = 0x007D
	propRecipientType         = 0x0C15
	propSenderName            = 0x0C1A
	propSenderEmail           = 0x0C1F
	propDeliveryTime          = 0x0E06
	propBody                  = 0x1000
	propRTFCompressed         = 0x1009
	propHTML                  = 0x1013
	propInternetMessageID     = 0x1035
	propDisplayName           = 0x3001
	propEmailAddress          = 0x3003
	propAttachData            = 0x3701
	propAttachFilename        = 0x3704
	propAttachMethod          = 0x3705
	propAttachLongFilename    = 0x3707
	propAttachMIMETag         = 0x370E
	propAttachContentID       = 0x3712
	propSMTPAddress           = 0x39FE
	propInternetCodepage      = 0x3FDE
	propMessageCodepage       = 0x3FFD
	propSenderSMTPAddress     = 0x5D01
	propSentRepresentingSMTP  = 0x5D02
)

// Property types.
const (
	typeInt32   = 0x0003
	typeString8 = 0x001E
	typeUnicode = 0x001F
	typeSysTime = 0x0040
	typeBinary  = 0x0102
	typeObject  = 0x000D
)

// Recipient types (PR_RECIPIENT_TYPE).
const (
	RecipientTo  = 1
	RecipientCc  = 2
	RecipientBcc = 3
)

type Recipient struct {
	Name  string
	Email string
	Type  int
}

type Attachment struct {
	Filename  string
	MIMEType  string
	ContentID string
	Data      []byte
	// Embedded is set for an attached message (forwarded as attachment).
	Embedded *Message
}

// Message is the content of a .msg file.
type Message struct {
	Class       string
	Subject     string
	SenderName  string
	SenderEmail string
	MessageID   string
	Date        time.Time
	// TransportHeaders are the original internet headers, when the message
	// was received from the internet.
	TransportHeaders string
	Body             string
	HTML             string
	// HTMLFromRTF is set when HTML was extracted from the compressed RTF
	// body, the only body of many messages.
	HTMLFromRTF bool
	Recipients  []Recipient
	Attachments []Attachment
}

// IsMsg reports whether data is a compound file holding a message.
func IsMsg(data []byte) bool {
	f, err := cfb.Open(data)
	if err != nil {
		return false
	}
	for _, e := range f.Entries() {
		if strings.HasPrefix(e.Name, "__substg1.0_") {
			return true
		}
	}
	return false
}

// Read parses a .msg file.
func Read(data []byte) (*Message, error) {
	f, err := cfb.Open(data)
	if err != nil {
		return nil, err
	}
	r := &reader{file: f}
	if !r.has("__properties_version1.0") && !r.has("__substg1.0_0037001F") && !r.has("__substg1.0_0037001E") && !r.has("__substg1.0_001A001F") {
		return nil, errors.New("msg: not an Outlook message")
	}
	return r.message("", 32, 0)
}

type reader struct {
	file *cfb.File
}

func (r *reader) has(path string) bool {
	_, ok := r.file.Find(path)
	return ok
}

// properties reads the fixed length properties of a storage. The header
// is 32 bytes for the top message, 24 for an embedded one, 8 for
// recipients and attachments.
func (r *reader) properties(prefix string, headerSize int) map[uint16][8]byte {
	props := map[uint16][8]byte{}
	entry, ok := r.file.Find(prefix + "__properties_version1.0")
	if !ok {
		return props
	}
	data, err := r.file.ReadStream(entry)
	if err != nil {
		return props
	}
	for offset := headerSize; offset+16 <= len(data); offset += 16 {
		tag := binary.LittleEndian.Uint32(data[offset:])
		var value [8]byte
		copy(value[:], data[offset+8:offset+16])
		props[uint16(tag>>16)] = value
	}
	return props
}

func (r *reader) stream(prefix string, id, typ uint16) ([]byte, bool) {
	entry, ok := r.file.Find(fmt.Sprintf("%s__substg1.0_%04X%04X", prefix, id, typ))
	if !ok {
		return nil, false
	}
	data, err := r.file.ReadStream(entry)
	return data, err == nil
}

// text reads a string property, Unicode or 8-bit in the message codepage.
func (r *reader) text(prefix string, id uint16, codepage int) string {
	if data, ok := r.stream(prefix, id, typeUnicode); ok {
		return decodeUTF16(data)
	}
	if data, ok := r.stream(prefix, id, typeString8); ok {
		return strings.TrimRight(decodeCodepage(data, codepage), "\x00")
	}
	return ""
}

func (r *reader) message(prefix string, headerSize, depth int) (*Message, error) {
	if depth > maxDepth {
		return nil, errors.New("msg: too many embedded messages")
	}
	props := r.properties(prefix, headerSize)
	codepage := int32Prop(props, propInternetCodepage)
	if codepage == 0 {
		codepage = int32Prop(props, propMessageCodepage)
	}

	m := &Message{
		Class:            r.text(prefix, propMessageClass, codepage),
		Subject:          r.text(prefix, propSubject, codepage),
		MessageID:        r.text(prefix, propInternetMessageID, codepage),
		TransportHeaders: r.text(prefix, propTransportHeaders, codepage),
		Body:             r.text(prefix, propBody, codepage),
		SenderName:       r.text(prefix, propSenderName, codepage),
	}
	for _, id := range []uint16{propSenderSMTPAddress, propSentRepresentingSMTP, propSenderEmail, propSentRepresentingEmail} {
		if email := r.text(prefix, id, codepage); strings.Contains(email, "@") {
			m.SenderEmail = email
			break
		}
	}
	if m.SenderName == "" {
		m.SenderName = r.text(prefix, propSentRepresentingName, codepage)
	}
	for _, id := range []uint16{propDeliveryTime, propClientSubmitTime} {
		if t := timeProp(props, id); !t.IsZero() {
			m.Date = t
			break
		}
	}

	if html, ok := r.stream(prefix, propHTML, typeBinary); ok {
		m.HTML = strings.TrimRight(decodeCodepage(html, codepage), "\x00")
	} else if html := r.text(prefix, propHTML, codepage); html != "" {
		m.HTML = html
	} else if compressed, ok := r.stream(prefix, propRTFCompressed, typeBinary); ok && len(compressed) > 0 {
		if rtf, err := DecompressRTF(compressed); err == nil {
			if html, ok := HTMLFromRTF(rtf); ok {
				m.HTML, m.HTMLFromRTF = html, true
			}
		}
	}

	for _, e := range r.file.Entries() {
		if e.Type != cfb.TypeStorage || !strings.HasPrefix(e.Path, prefix) || strings.Contains(e.Path[len(prefix):], "/") {
			continue
		}
		storage := e.Path + "/"
		switch {
		case strings.HasPrefix(e.Name, "__recip_version1.0_"):
			rp := r.properties(storage, 8)
			recipient := Recipient{Name: r.text(storage, propDisplayName, codepage), Type: int32Prop(rp, propRecipientType)}
			for _, id := range []uint16{propSMTPAddress, propEmailAddress} {
				if email := r.text(storage, id, codepage); strings.Contains(email, "@") {
					recipient.Email = email
					break
				}
			}
			m.Recipients = append(m.Recipients, recipient)
		case strings.HasPrefix(e.Name, "__attach_version1.0_"):
			attachment, err := r.attachment(storage, codepage, depth)
			if err != nil {
				return nil, err
			}
			m.Attachments = append(m.Attachments, attachment)
		}
	}
	return m, nil
}

func (r *reader) attachment(storage string, codepage, depth int) (Attachment, error) {
	a := Attachment{
		Filename:  r.text(storage, propAttachLongFilename, codepage),
		MIMEType:  r.text(storage, propAttachMIMETag, codepage),
		ContentID: r.text(storage, propAttachContentID, codepage),
	}
	if a.Filename == "" {
		a.Filename = r.text(storage, propAttachFilename, codepage)
	}
	if data, ok := r.stream(storage, propAttachData, typeBinary); ok {
		a.Data = data
		return a, nil
	}
	embedded := fmt.Sprintf("%s__substg1.0_%04X%04X/", storage, propAttachData, typeObject)
	if r.has(strings.TrimSuffix(embedded, "/")) {
		m, err := r.message(embedded, 24, depth+1)
		if err != nil {
			return a, err
		}
		a.Embedded = m
		if a.Filename == "" {
			a.Filename = m.Subject + ".eml"
		}
	}
	return a, nil
}

func int32Prop(props map[uint16][8]byte, id uint16) int {
	value, ok := props[id]
	if !ok {
		return 0
	}
	return int(int32(binary.LittleEndian.Uint32(value[:4])))
}

// timeProp converts a FILETIME (100 ns intervals since 1601) property.
func timeProp(props map[uint16][8]byte, id uint16) time.Time {
	value, ok := props[id]
	if !ok {
		return time.Time{}
	}
	ticks := binary.LittleEndian.Uint64(value[:])
	if ticks == 0 {
		return time.Time{}
	}
	const epochDifference = 116444736000000000 // 1601-01-01 to 1970-01-01
	if ticks < epochDifference {
		return time.Time{}
	}
	unix100ns := ticks - epochDifference
	return time.Unix(int64(unix100ns/10000000), int64(unix100ns%10000000)*100).UTC()
}

func decodeUTF16(data []byte) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(data[i:]))
	}
	return strings.TrimRight(string(utf16.Decode(units)), "\x00")
}

// codepages maps the Windows codepages found in messages to encodings.
var codepages = map[int]encoding.Encoding{
	874: charmap.Windows874, 1250: charmap.Windows1250, 1251: charmap.Windows1251, 1252: charmap.Windows1252,
	1253: charmap.Windows1253, 1254: charmap.Windows1254, 1255: charmap.Windows1255, 1256: charmap.Windows1256,
	1257: charmap.Windows1257, 1258: charmap.Windows1258, 28591: charmap.ISO8859_1, 28592: charmap.ISO8859_2,
	28605: charmap.ISO8859_15, 20866: charmap.KOI8R, 932: japanese.ShiftJIS, 50220: japanese.ISO2022JP,
	51932: japanese.EUCJP, 936: simplifiedchinese.GBK, 54936: simplifiedchinese.GB18030,
	949: korean.EUCKR, 950: traditionalchinese.Big5,
}

// decodeCodepage converts 8-bit text to UTF-8. Unknown codepages are read
// as windows-1252, the most common one.
func decodeCodepage(data []byte, codepage int) string {
	if codepage == 65001 || codepage == 20127 {
		return string(data)
	}
	enc, ok := codepages[codepage]
	if !ok {
		enc = charmap.Windows1252
	}
	decoded, err := enc.NewDecoder().Bytes(data)
	if err != nil {
		return string(data)
	}
	return string(decoded)
}
