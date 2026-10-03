package mailauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The dkim-*.eml vectors are signed by dkimpy (see testdata/gen_dkim.py).
func dkimResolver(t *testing.T) *fakeResolver {
	t.Helper()
	key, err := os.ReadFile("testdata/dkim-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	return &fakeResolver{txt: map[string][]string{"test._domainkey.example.com": {strings.TrimSpace(string(key))}}}
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func verifyOne(t *testing.T, resolver Resolver, raw []byte) DKIMResult {
	t.Helper()
	results := VerifyDKIM(context.Background(), resolver, ParseMessage(raw))
	if len(results) != 1 {
		t.Fatalf("%d results, want 1", len(results))
	}
	return results[0]
}

func TestVerifyDKIMVectors(t *testing.T) {
	resolver := dkimResolver(t)
	for _, name := range []string{"dkim-relaxed-relaxed.eml", "dkim-simple-simple.eml", "dkim-relaxed-simple.eml", "dkim-simple-relaxed.eml", "dkim-length.eml"} {
		t.Run(name, func(t *testing.T) {
			got := verifyOne(t, resolver, readVector(t, name))
			if got.Result != ResultPass {
				t.Fatalf("result %s: %s", got.Result, got.Reason)
			}
			if got.Domain != "example.com" || got.Selector != "test" || got.KeyBits != 2048 || len(got.Headers) != 7 {
				t.Errorf("result = %+v", got)
			}
			if got.BodyLimit != (name == "dkim-length.eml") {
				t.Errorf("BodyLimit = %v", got.BodyLimit)
			}
		})
	}
}

func TestVerifyDKIMTampered(t *testing.T) {
	resolver := dkimResolver(t)
	relaxed := readVector(t, "dkim-relaxed-relaxed.eml")
	tests := []struct {
		name   string
		raw    []byte
		result string
		reason string
	}{
		{"body changed", bytes.Replace(relaxed, []byte("We lost"), []byte("We won"), 1), ResultFail, "corps"},
		{"subject changed", bytes.Replace(relaxed, []byte("Is dinner"), []byte("Is lunch"), 1), ResultFail, "signature invalide"},
		{"oversigned header added", bytes.Replace(relaxed, []byte("Date:"), []byte("Reply-To: evil@example.org\r\nDate:"), 1), ResultFail, "signature invalide"},
		{"content appended without l=", append(bytes.Clone(relaxed), "Appended\r\n"...), ResultFail, "corps"},
		{"whitespace changes in relaxed", bytes.Replace(relaxed, []byte("Hi.  \r\n"), []byte("Hi.\t\r\n"), 1), ResultPass, ""},
		{"LF line endings", bytes.ReplaceAll(relaxed, []byte("\r\n"), []byte("\n")), ResultPass, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyOne(t, resolver, tt.raw)
			if got.Result != tt.result || !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("result %s (%s), want %s (%s)", got.Result, got.Reason, tt.result, tt.reason)
			}
		})
	}

	// l= lets content be appended: still valid, flagged.
	length := append(readVector(t, "dkim-length.eml"), "Click https://evil.example/\r\n"...)
	if got := verifyOne(t, resolver, length); got.Result != ResultPass || !got.BodyLimit {
		t.Errorf("appended content with l=: %+v", got)
	}
}

func TestVerifyDKIMKeyErrors(t *testing.T) {
	raw := readVector(t, "dkim-relaxed-relaxed.eml")
	tests := []struct {
		name     string
		resolver *fakeResolver
		result   string
		reason   string
	}{
		{"no key", &fakeResolver{}, ResultPermError, "introuvable"},
		{"DNS failure", &fakeResolver{txt: map[string][]string{"test._domainkey.example.com": {"x"}}, temp: map[string]bool{"test._domainkey.example.com": true}}, ResultTempError, ""},
		{"revoked", &fakeResolver{txt: map[string][]string{"test._domainkey.example.com": {"v=DKIM1; p="}}}, ResultPermError, "révoquée"},
		{"wrong key type", &fakeResolver{txt: map[string][]string{"test._domainkey.example.com": {"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32))}}}, ResultPermError, "type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyOne(t, tt.resolver, raw)
			if got.Result != tt.result || !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("result %s (%s), want %s (%s)", got.Result, got.Reason, tt.result, tt.reason)
			}
		})
	}

	// The key was rotated since the mail was sent: the signature fails.
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rotated.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{txt: map[string][]string{"test._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)}}}
	if got := verifyOne(t, resolver, raw); got.Result != ResultFail || !strings.Contains(got.Reason, "clé changée") {
		t.Errorf("rotated key: %s (%s)", got.Result, got.Reason)
	}
}

func TestVerifyDKIMSignatureErrors(t *testing.T) {
	resolver := dkimResolver(t)
	raw := string(readVector(t, "dkim-relaxed-relaxed.eml"))
	tests := []struct {
		name, old, new, reason string
	}{
		{"rsa-sha1", "a=rsa-sha256", "a=rsa-sha1", "rsa-sha1"},
		{"from not signed", "from :", "to :", "From"}, // h= signs From twice
		{"unknown version", "v=1;", "v=2;", "version"},
		{"identity outside domain", "i=@example.com", "i=@evil.example", "identité"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyOne(t, resolver, []byte(strings.ReplaceAll(raw, tt.old, tt.new)))
			if got.Result != ResultPermError || !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("result %s (%s), want permerror (%s)", got.Result, got.Reason, tt.reason)
			}
		})
	}
}

// Ed25519 (RFC 8463): the canonicalization is validated by the dkimpy
// vectors, this test covers the key and signature handling.
func TestVerifyDKIMEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := "From: joe@example.com\r\nSubject: ed25519\r\n\r\nHello\r\n"
	bodyHash := sha256.Sum256([]byte("Hello\r\n"))
	signature := "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed;\r\n" +
		" h=from:subject; bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]) + "; b=\r\n"
	m := ParseMessage([]byte(signature + message))
	h := sha256.New()
	h.Write([]byte(canonicalHeader(m.Fields[1].Raw, "relaxed")))
	h.Write([]byte(canonicalHeader(m.Fields[2].Raw, "relaxed")))
	h.Write([]byte(strings.TrimSuffix(canonicalHeader(removeSignatureValue(m.Fields[0].Raw), "relaxed"), "\r\n")))
	b := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, h.Sum(nil)))
	signed := strings.Replace(signature, "b=\r\n", "b="+b+"\r\n", 1) + message

	resolver := &fakeResolver{txt: map[string][]string{"ed._domainkey.example.com": {"v=DKIM1; k=ed25519; t=y; p=" + base64.StdEncoding.EncodeToString(pub)}}}
	got := verifyOne(t, resolver, []byte(signed))
	if got.Result != ResultPass || !got.Testing || got.KeyBits != 256 {
		t.Errorf("ed25519: %+v", got)
	}
	tampered := strings.Replace(signed, "Subject: ed25519", "Subject: changed", 1)
	if got := verifyOne(t, resolver, []byte(tampered)); got.Result != ResultFail {
		t.Errorf("tampered ed25519: %+v", got)
	}
}

func TestCanonicalBody(t *testing.T) {
	tests := []struct{ body, simple, relaxed string }{
		{"", "\r\n", ""},
		{"\r\n", "\r\n", ""},
		{"\r\n\r\n\r\n", "\r\n", ""},
		{"a  b \t\r\n\r\n", "a  b \t\r\n", "a b\r\n"},
		{"no final CRLF  ", "no final CRLF  \r\n", "no final CRLF\r\n"},
		{" leading\r\n", " leading\r\n", " leading\r\n"},
	}
	for _, tt := range tests {
		if got := string(canonicalBody([]byte(tt.body), "simple")); got != tt.simple {
			t.Errorf("simple(%q) = %q, want %q", tt.body, got, tt.simple)
		}
		if got := string(canonicalBody([]byte(tt.body), "relaxed")); got != tt.relaxed {
			t.Errorf("relaxed(%q) = %q, want %q", tt.body, got, tt.relaxed)
		}
	}
}

func TestDKIMSignedFields(t *testing.T) {
	resolver := dkimResolver(t)
	relaxed := readVector(t, "dkim-relaxed-relaxed.eml")
	check := func(t *testing.T, got DKIMResult, bodyHash string) {
		t.Helper()
		var names []string
		var indexes []int
		for _, f := range got.Fields {
			names, indexes = append(names, f.Name), append(indexes, f.Index)
		}
		if strings.Join(names, ",") != "from,to,subject,date,message-id,from,reply-to" || fmt.Sprint(indexes) != "[1 2 3 4 5 -1 -1]" {
			t.Errorf("fields %v %v", names, indexes)
		}
		if subject := got.Fields[2]; subject.Canonical != "subject:Is dinner ready? folded continuation\r\n" || !strings.HasPrefix(subject.Raw, "Subject:   Is dinner\t") {
			t.Errorf("subject = %q / %q", subject.Raw, subject.Canonical)
		}
		if got.HeaderCanon != "relaxed" || got.BodyCanon != "relaxed" || got.SignatureField != 0 || got.BodyHash != bodyHash {
			t.Errorf("canon %s/%s, field %d, body hash %q", got.HeaderCanon, got.BodyCanon, got.SignatureField, got.BodyHash)
		}
		if !strings.HasPrefix(got.SignatureInput, "dkim-signature:v=1; a=rsa-sha256;") || !strings.HasSuffix(got.SignatureInput, "b=") {
			t.Errorf("signature input %q", got.SignatureInput)
		}
		if len(got.Tags) == 0 || got.Tags[0] != (Tag{"v", "1"}) {
			t.Errorf("tags %v", got.Tags)
		}
	}
	t.Run("pass", func(t *testing.T) { check(t, verifyOne(t, resolver, relaxed), "ok") })
	t.Run("body changed", func(t *testing.T) {
		check(t, verifyOne(t, resolver, bytes.Replace(relaxed, []byte("We lost"), []byte("We won"), 1)), "différent")
	})
	t.Run("no key", func(t *testing.T) { check(t, verifyOne(t, &fakeResolver{}, relaxed), "ok") })
}
