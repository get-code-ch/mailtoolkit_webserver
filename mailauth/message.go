// Package mailauth verifies the authentication of a received mail (SPF,
// DKIM, DMARC) and parses its trace headers. DNS queries go through a
// Resolver, net.DefaultResolver in production.
package mailauth

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// Resolver is the subset of *net.Resolver used by the checks.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Field is a header field, kept as received for the DKIM verification.
type Field struct {
	Name string
	// Raw is the whole field, folding and final CRLF included.
	Raw string
	// Value is the unfolded value, without surrounding spaces.
	Value string
}

// Message is a mail split into header fields and body, with CRLF line
// endings as on the wire.
type Message struct {
	Fields []Field
	Body   []byte
}

// ParseMessage splits a raw mail. Bare LF line endings (mails saved on
// Unix) are converted to CRLF, the form signatures are computed on.
func ParseMessage(raw []byte) Message {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	raw = bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n"))

	header, body, found := bytes.Cut(raw, []byte("\r\n\r\n"))
	if found {
		header = append(header, '\r', '\n')
	} else {
		body = nil
	}

	var m Message
	m.Body = body
	for _, line := range strings.SplitAfter(string(header), "\r\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(m.Fields) > 0 {
			last := &m.Fields[len(m.Fields)-1]
			last.Raw += line
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t") {
			continue // not a header field (e.g. an mbox "From " line)
		}
		m.Fields = append(m.Fields, Field{Name: name, Raw: line})
	}
	for i := range m.Fields {
		_, value, _ := strings.Cut(m.Fields[i].Raw, ":")
		m.Fields[i].Value = strings.TrimSpace(unfold(value))
	}
	return m
}

// Values returns the values of the fields called name, top to bottom.
func (m Message) Values(name string) []string {
	var values []string
	for _, f := range m.Fields {
		if strings.EqualFold(f.Name, name) {
			values = append(values, f.Value)
		}
	}
	return values
}

// Get returns the first value of the field called name.
func (m Message) Get(name string) string {
	if values := m.Values(name); len(values) > 0 {
		return values[0]
	}
	return ""
}

func unfold(s string) string {
	return strings.NewReplacer("\r\n", "", "\n", "").Replace(s)
}

// isNotFound tells a definitive DNS answer (no such name, no record) from a
// temporary failure.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// domainOf returns the lowercase domain of an address, without brackets.
func domainOf(address string) string {
	address = strings.Trim(strings.TrimSpace(address), "<>")
	if i := strings.LastIndexByte(address, '@'); i >= 0 {
		address = address[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(address), ".")
}
