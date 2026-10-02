package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testIngestToken = "0123456789abcdef0123456789abcdef"

func postIngest(handler http.Handler, token, to string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("X-Envelope-From", "<user@example.org>")
	request.Header.Set("X-Envelope-To", to)
	request.RemoteAddr = "172.71.1.2:4321" // a Cloudflare address
	request.Header.Set("CF-Connecting-IP", "2001:db8::7")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestIngest(t *testing.T) {
	s := newTestServer(t)
	s.ingestToken, s.hostname, s.behindCloudflare = testIngestToken, "mtk.example.test", true
	handler := s.routes(t.TempDir())
	mailbox, err := s.store.Create()
	if err != nil {
		t.Fatal(err)
	}
	suspect := readTestdata(t, "multipartcomplex.eml")
	carrier := buildCarrier("Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"suspect.eml\"\r\n\r\n" + string(suspect))

	for name, tt := range map[string]struct {
		token, to string
		body      []byte
		code      int
	}{
		"no token":          {"", mailbox.Address, carrier, http.StatusUnauthorized},
		"wrong token":       {strings.Repeat("x", 32), mailbox.Address, carrier, http.StatusUnauthorized},
		"unknown recipient": {testIngestToken, "nobody@analyzer.test", carrier, http.StatusNotFound},
		"foreign domain":    {testIngestToken, "x@relay.example", carrier, http.StatusNotFound},
		"empty":             {testIngestToken, mailbox.Address, nil, http.StatusBadRequest},
		"too large":         {testIngestToken, mailbox.Address, make([]byte, 2<<20), http.StatusRequestEntityTooLarge},
		"accepted":          {testIngestToken, "<" + strings.ToUpper(mailbox.Address) + ">", carrier, http.StatusNoContent},
	} {
		if got := postIngest(handler, tt.token, tt.to, tt.body).Code; got != tt.code {
			t.Errorf("%s: %d, want %d", name, got, tt.code)
		}
	}

	submissions, err := s.store.Submissions(mailbox.Token)
	if err != nil || len(submissions) != 1 {
		t.Fatalf("%d submissions, %v", len(submissions), err)
	}
	sub := submissions[0]
	if sub.Envelope.Mode != modeIngest || sub.Envelope.MailFrom != "user@example.org" || sub.Envelope.RemoteAddr != "2001:db8::7" ||
		len(sub.Analyzed) != 1 || sub.Analyzed[0].Subject != "Hello Bonjour Coucou !!" {
		t.Errorf("submission = %+v", sub)
	}
	raw, _, err := s.store.AnalyzedRaw(mailbox.Token, sub.ID, 1)
	if err != nil || !bytes.Equal(raw, suspect) {
		t.Errorf("attached mail not kept byte for byte (%v)", err)
	}
}

func TestIngestDisabled(t *testing.T) {
	s := newTestServer(t)
	if got := postIngest(s.routes(t.TempDir()), testIngestToken, "a@analyzer.test", []byte("x")).Code; got != http.StatusNotFound {
		t.Errorf("ingest without token configured: %d, want 404", got)
	}
}

func TestClientIP(t *testing.T) {
	s := &server{behindCloudflare: true}
	for _, tt := range []struct {
		remote, header, want string
	}{
		{"172.71.1.2:443", "198.51.100.9", "198.51.100.9"},   // from Cloudflare
		{"[2606:4700::1]:443", "2001:db8::1", "2001:db8::1"}, // from Cloudflare, IPv6
		{"203.0.113.5:443", "198.51.100.9", "203.0.113.5"},   // forged by a direct client
		{"172.71.1.2:443", "not an address", "172.71.1.2"},   // invalid header
		{"172.71.1.2:443", "", "172.71.1.2"},                 // no header
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tt.remote
		if tt.header != "" {
			r.Header.Set("CF-Connecting-IP", tt.header)
		}
		if got := s.clientIP(r); got != tt.want {
			t.Errorf("clientIP(%s, %q) = %s, want %s", tt.remote, tt.header, got, tt.want)
		}
	}
	direct := &server{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "172.71.1.2:443"
	r.Header.Set("CF-Connecting-IP", "198.51.100.9")
	if got := direct.clientIP(r); got != "172.71.1.2" {
		t.Errorf("header trusted while behind_cloudflare is off: %s", got)
	}
}
