package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// The vectors are signed by OpenSSL (see testdata/gen.sh) with a test PKI:
// root, intermediate (whose key answers OCSP and signs the CRL), and an
// organization-validated certificate for signer@example.com.

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readFile(t, name))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func readKey(t *testing.T, name string) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode(readFile(t, name))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key.(crypto.Signer)
}

// pki answers the OCSP and CRL requests of http://pki.test/.
type pki struct {
	t       *testing.T
	issuer  *x509.Certificate
	key     crypto.Signer
	revoked bool
	ocspOff bool
	crlOff  bool
	hits    map[string]int
}

func (p *pki) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	p.hits[req.URL.Path]++
	switch {
	case req.URL.Host != "pki.test":
		recorder.WriteHeader(http.StatusNotFound)
	case req.URL.Path == "/ocsp" && !p.ocspOff:
		body, _ := io.ReadAll(req.Body)
		request, err := ocsp.ParseRequest(body)
		if err != nil {
			p.t.Fatal(err)
		}
		template := ocsp.Response{Status: ocsp.Good, SerialNumber: request.SerialNumber,
			ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour)}
		if p.revoked {
			template.Status, template.RevokedAt, template.RevocationReason = ocsp.Revoked, time.Now().Add(-48*time.Hour), ocsp.KeyCompromise
		}
		response, err := ocsp.CreateResponse(p.issuer, p.issuer, template, p.key)
		if err != nil {
			p.t.Fatal(err)
		}
		recorder.Write(response)
	case req.URL.Path == "/ica.crl" && !p.crlOff:
		template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour)}
		if p.revoked {
			template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(4242), RevocationTime: time.Now().Add(-48 * time.Hour), ReasonCode: 1}}
		}
		list, err := x509.CreateRevocationList(rand.Reader, template, p.issuer, p.key)
		if err != nil {
			p.t.Fatal(err)
		}
		recorder.Write(list)
	default:
		recorder.WriteHeader(http.StatusServiceUnavailable)
	}
	return recorder.Result(), nil
}

func newVerifier(t *testing.T) (*Verifier, *pki) {
	roots := x509.NewCertPool()
	roots.AddCert(readCert(t, "root.pem"))
	p := &pki{t: t, issuer: readCert(t, "ica.pem"), key: readKey(t, "ica.key"), hits: map[string]int{}}
	checker := NewRevocationChecker()
	checker.Client.Transport = p
	return &Verifier{Roots: roots, Revocation: checker}, p
}

func TestVerifyVectors(t *testing.T) {
	for _, name := range []string{"detached.eml", "ber.eml", "streamed.eml", "opaque.eml"} {
		t.Run(name, func(t *testing.T) {
			v, _ := newVerifier(t)
			r := v.Verify(context.Background(), readFile(t, name), "signer@example.com")
			if r.Status != StatusValid || !r.Trusted() || r.Integrity != "ok" || r.Revocation.Status != RevocationGood || r.Revocation.Method != "OCSP" {
				t.Fatalf("%+v", r)
			}
			s := r.Signer
			if s.Organization != "Example Org" || s.OrganizationID != "NTRCH-CHE-123.456.789" || s.Validation != "organization" ||
				!s.IdentityVerified() || len(r.Chain) != 3 || r.SigningTime.IsZero() || r.DigestAlgorithm != "SHA-256" {
				t.Errorf("signer %+v, chain %d, time %v", s, len(r.Chain), r.SigningTime)
			}
			if r.Opaque != strings.Contains(name, "opaque") && r.Opaque != strings.Contains(name, "streamed") {
				t.Errorf("opaque = %v", r.Opaque)
			}
		})
	}
}

func TestVerifyFailures(t *testing.T) {
	detached := readFile(t, "detached.eml")

	t.Run("content modified", func(t *testing.T) {
		v, _ := newVerifier(t)
		r := v.Verify(context.Background(), bytes.Replace(detached, []byte("2026-17"), []byte("2026-71"), 1), "signer@example.com")
		if r.Status != StatusInvalid || r.Integrity != "différent" || r.Trusted() {
			t.Errorf("%+v", r)
		}
	})
	t.Run("other sender", func(t *testing.T) {
		v, _ := newVerifier(t)
		r := v.Verify(context.Background(), detached, "ceo@example.com")
		if r.Status != StatusValid || r.FromMatch || r.Trusted() || !strings.Contains(r.Reason, "délivré pour signer@example.com") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("unknown authority", func(t *testing.T) {
		v, _ := newVerifier(t)
		v.Roots = x509.NewCertPool()
		r := v.Verify(context.Background(), detached, "signer@example.com")
		if r.Status != StatusUntrusted || !strings.Contains(r.Reason, "autorité de certification inconnue") || r.Revocation.Status != "" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("self-signed", func(t *testing.T) {
		v, _ := newVerifier(t)
		r := v.Verify(context.Background(), readFile(t, "selfsigned.eml"), "signer@example.com")
		if r.Status != StatusUntrusted || r.Integrity != "ok" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("revoked by OCSP", func(t *testing.T) {
		v, p := newVerifier(t)
		p.revoked = true
		r := v.Verify(context.Background(), detached, "signer@example.com")
		if r.Revocation.Status != RevocationRevoked || r.Revocation.Reason != "clé privée compromise" || r.Trusted() || !strings.Contains(r.Reason, "révoqué") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("revoked by CRL", func(t *testing.T) {
		v, p := newVerifier(t)
		p.revoked, p.ocspOff = true, true
		r := v.Verify(context.Background(), detached, "signer@example.com")
		if r.Revocation.Status != RevocationRevoked || r.Revocation.Method != "CRL" {
			t.Errorf("%+v", r.Revocation)
		}
		// Cached: the CRL is not downloaded again.
		v.Verify(context.Background(), detached, "signer@example.com")
		if p.hits["/ica.crl"] != 1 {
			t.Errorf("CRL downloaded %d times", p.hits["/ica.crl"])
		}
	})
	t.Run("revocation services down", func(t *testing.T) {
		v, p := newVerifier(t)
		p.ocspOff, p.crlOff = true, true
		r := v.Verify(context.Background(), detached, "signer@example.com")
		if r.Revocation.Status != RevocationUnknown || !r.Trusted() {
			t.Errorf("%+v", r.Revocation)
		}
	})
	t.Run("encrypted", func(t *testing.T) {
		v, _ := newVerifier(t)
		if r := v.Verify(context.Background(), readFile(t, "encrypted.eml"), "signer@example.com"); r.Status != StatusEncrypted {
			t.Errorf("%+v", r)
		}
	})
	t.Run("not signed", func(t *testing.T) {
		v, _ := newVerifier(t)
		if r := v.Verify(context.Background(), []byte("From: a@example.com\r\n\r\nHello\r\n"), "a@example.com"); r.Status != StatusNone {
			t.Errorf("%+v", r)
		}
	})
	t.Run("signed part inside a multipart", func(t *testing.T) {
		v, _ := newVerifier(t)
		crlf := bytes.ReplaceAll(bytes.ReplaceAll(detached, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
		header, body, _ := bytes.Cut(crlf, []byte("\r\n\r\n"))
		var inner []byte
		for _, line := range bytes.SplitAfter(header, []byte("\r\n")) {
			if bytes.HasPrefix(line, []byte("Content-Type")) || bytes.HasPrefix(line, []byte("\t")) || bytes.HasPrefix(line, []byte(" ")) {
				inner = append(inner, line...)
			}
		}
		wrapped := "From: signer@example.com\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" +
			strings.TrimRight(string(inner), "\r\n") + "\r\n\r\n" + string(body) + "\r\n--outer\r\nContent-Type: text/plain\r\n\r\nFooter\r\n--outer--\r\n"
		if r := v.Verify(context.Background(), []byte(wrapped), "signer@example.com"); r.Status != StatusValid {
			t.Errorf("%+v", r)
		}
	})
}

func TestBERToDER(t *testing.T) {
	tests := []struct{ ber, der string }{
		{"\x30\x80\x02\x01\x05\x00\x00", "\x30\x03\x02\x01\x05"},
		// constructed octet string segments become one primitive string
		{"\x24\x80\x04\x02ab\x04\x01c\x00\x00", "\x04\x03abc"},
		{"\x30\x03\x02\x01\x05", "\x30\x03\x02\x01\x05"},
	}
	for _, tt := range tests {
		got, err := berToDER([]byte(tt.ber))
		if err != nil || string(got) != tt.der {
			t.Errorf("%q: %q, %v", tt.ber, got, err)
		}
	}
	for _, bad := range []string{"\x30\x80\x02\x01", "\x30\x05\x02", "\x04\x80ab\x00\x00", ""} {
		if _, err := berToDER([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
