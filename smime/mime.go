package smime

import (
	"bytes"
	"encoding/base64"
	"errors"
	"mime"
	"strings"
)

// maxMIMEDepth bounds the search of a signature in nested parts.
const maxMIMEDepth = 4

// entity is a MIME entity, header and body, with CRLF line endings.
type entity struct {
	raw    []byte
	header []byte
	body   []byte
}

func splitEntity(raw []byte) entity {
	if bytes.HasPrefix(raw, []byte("\r\n")) {
		return entity{raw: raw, body: raw[2:]}
	}
	header, body, found := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !found {
		return entity{raw: raw, header: raw}
	}
	return entity{raw: raw, header: append(header, "\r\n"...), body: body}
}

// headerValue returns an unfolded header field of an entity.
func (e entity) headerValue(name string) string {
	var value strings.Builder
	in := false
	for _, line := range strings.SplitAfter(string(e.header), "\r\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if in {
				value.WriteString(" " + strings.TrimSpace(line))
			}
			continue
		}
		if in {
			break
		}
		field, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(field), name) {
			in = true
			value.WriteString(strings.TrimSpace(v))
		}
	}
	return value.String()
}

func (e entity) mediaType() (string, map[string]string) {
	t, params, err := mime.ParseMediaType(e.headerValue("Content-Type"))
	if err != nil {
		return "text/plain", nil
	}
	return t, params
}

// parts splits a multipart body, keeping each part byte for byte: the
// CRLF before a delimiter belongs to the delimiter (RFC 2046 §5.1.1).
func parts(body []byte, boundary string) [][]byte {
	delimiter := []byte("\r\n--" + boundary)
	data := append([]byte("\r\n"), body...)
	var result [][]byte
	start := -1
	for i := 0; ; {
		j := bytes.Index(data[i:], delimiter)
		if j < 0 {
			return result
		}
		j += i
		after := j + len(delimiter)
		if start >= 0 {
			result = append(result, data[start:j])
		}
		if bytes.HasPrefix(data[after:], []byte("--")) {
			return result
		}
		// The rest of the delimiter line (transport padding) is skipped.
		eol := bytes.Index(data[after:], []byte("\r\n"))
		if eol < 0 {
			return result
		}
		start = after + eol + 2
		i = start
	}
}

// signature is the signed content of a message and its CMS signature.
type signature struct {
	// content is the signed MIME entity of a detached signature (nil for
	// an opaque one, whose content is in the CMS structure).
	content []byte
	cms     []byte
	opaque  bool
}

var errNotSigned = errors.New("pas de signature S/MIME")

// findSignature looks for an S/MIME signed or encrypted entity: the
// message itself, or one of its parts (a footer added around it).
func findSignature(raw []byte) (signature, error) {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	raw = bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n"))
	return search(splitEntity(raw), 0)
}

func search(e entity, depth int) (signature, error) {
	mediaType, params := e.mediaType()
	switch mediaType {
	case "multipart/signed":
		protocol := strings.ToLower(params["protocol"])
		if protocol != "application/pkcs7-signature" && protocol != "application/x-pkcs7-signature" {
			return signature{}, errNotSigned // PGP/MIME and others
		}
		p := parts(e.body, params["boundary"])
		if len(p) != 2 {
			return signature{}, errors.New("message signé mal formé : il doit avoir deux parties")
		}
		cms, err := decodeBody(splitEntity(p[1]))
		if err != nil {
			return signature{}, err
		}
		return signature{content: p[0], cms: cms}, nil
	case "application/pkcs7-mime", "application/x-pkcs7-mime":
		cms, err := decodeBody(e)
		if err != nil {
			return signature{}, err
		}
		return signature{cms: cms, opaque: true}, nil
	}
	if strings.HasPrefix(mediaType, "multipart/") && depth < maxMIMEDepth {
		for _, part := range parts(e.body, params["boundary"]) {
			if s, err := search(splitEntity(part), depth+1); !errors.Is(err, errNotSigned) {
				return s, err
			}
		}
	}
	return signature{}, errNotSigned
}

func decodeBody(e entity) ([]byte, error) {
	switch strings.ToLower(e.headerValue("Content-Transfer-Encoding")) {
	case "base64":
		clean := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(e.body))
		data, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, errors.New("signature S/MIME illisible (base64)")
		}
		return data, nil
	case "", "binary", "7bit", "8bit":
		return e.body, nil
	}
	return nil, errors.New("encodage de la signature S/MIME non supporté")
}
