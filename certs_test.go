package main

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/internal/testcert"
)

func writeCert(t *testing.T, dir string, modTime time.Time) []byte {
	t.Helper()
	certPEM, keyPEM, cert := testcert.Generate(t, "mx.analyzer.test")
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM} {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, modTime, modTime); err != nil {
			t.Fatal(err)
		}
	}
	return cert.Certificate[0]
}

func served(t *testing.T, r *certReloader) []byte {
	t.Helper()
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	return cert.Certificate[0]
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	first := writeCert(t, dir, time.Now().Add(-time.Hour))

	r, err := newCertReloader(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	r.interval = 0
	if !bytes.Equal(served(t, r), first) {
		t.Fatal("initial certificate not served")
	}

	second := writeCert(t, dir, time.Now())
	if !bytes.Equal(served(t, r), second) {
		t.Error("renewed certificate not served")
	}

	// A broken renewal keeps the previous certificate.
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("broken"), 0o600)
	if !bytes.Equal(served(t, r), second) {
		t.Error("previous certificate not kept after a failed reload")
	}
}

func TestCertReloaderMissingFiles(t *testing.T) {
	if _, err := newCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Error("missing certificate accepted")
	}
}
