package mailauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// maxSignatures is the number of DKIM signatures verified per mail.
const maxSignatures = 5

// DKIMResult is the verification of one DKIM-Signature.
type DKIMResult struct {
	Result    string // pass, fail, neutral, permerror, temperror
	Domain    string
	Selector  string
	Algorithm string
	// Headers are the signed header fields.
	Headers []string
	Reason  string
	KeyBits int
	// Testing is set when the key is published in test mode (t=y).
	Testing bool
	// BodyLimit is set when only the beginning of the body is signed (l=),
	// content can be appended without breaking the signature.
	BodyLimit bool
	Signed    time.Time

	// SignatureField is the index of the DKIM-Signature field in the
	// message.
	SignatureField int
	HeaderCanon    string
	BodyCanon      string
	// Tags are the tags of the signature, in order.
	Tags []Tag
	// Fields are the fields named in h=, in order, with the exact text
	// hashed for each of them.
	Fields []SignedField
	// BodyHash is "ok" when the body matches bh=, "différent" when it was
	// modified, empty when it was not computed.
	BodyHash string
	// BodyHashComputed is the hash of the body as received (base64), and
	// BodyLength the length of the canonicalized body hashed.
	BodyHashComputed string
	BodyLength       int
	// BodyHint explains a body hash mismatch when a variant of the body
	// matches bh=.
	BodyHint string
	// HeaderHash is "ok" when the signed header fields verify with the
	// key, "différent" when they do not, empty when not checked.
	HeaderHash string
	// HeaderHint names the field whose change breaks the signature, when
	// it could be found.
	HeaderHint string
	// SignatureInput is the DKIM-Signature field as hashed last, with an
	// empty b= and without its final CRLF.
	SignatureInput string
}

// SignedField is a header field named in the h= tag of a signature.
type SignedField struct {
	// Name is the name as written in h=.
	Name string
	// Index is the field of the message hashed for this name (the lowest
	// one not used yet), -1 when the message has none: signing an absent
	// field prevents adding it without breaking the signature.
	Index int
	Raw   string
	// Canonical is the text hashed, after canonicalization.
	Canonical string
	// Modified is set on the field found to break the signature, Note
	// telling how.
	Modified bool
	Note     string
}

// Tag is a tag=value pair of a DKIM or ARC tag-list.
type Tag struct {
	Name  string
	Value string
}

// ParseTags returns the tags of a tag-list in order, ignoring malformed
// parts, for display. Whitespace is removed from the values.
func ParseTags(s string) []Tag {
	var tags []Tag
	for _, part := range strings.Split(s, ";") {
		name, value, ok := strings.Cut(part, "=")
		if name = strings.TrimSpace(name); !ok || name == "" {
			continue
		}
		tags = append(tags, Tag{name, strings.Join(strings.Fields(value), "")})
	}
	return tags
}

// VerifyDKIM verifies the DKIM signatures of a message, top to bottom.
func VerifyDKIM(ctx context.Context, resolver Resolver, m Message) []DKIMResult {
	var results []DKIMResult
	for i, f := range m.Fields {
		if !strings.EqualFold(f.Name, "DKIM-Signature") {
			continue
		}
		if len(results) == maxSignatures {
			break
		}
		results = append(results, verifySignature(ctx, resolver, m, i))
	}
	return results
}

func verifySignature(ctx context.Context, resolver Resolver, m Message, index int) DKIMResult {
	field := m.Fields[index]
	result := DKIMResult{SignatureField: index, Tags: ParseTags(field.Value)}
	fail := func(status, format string, args ...any) DKIMResult {
		result.Result, result.Reason = status, fmt.Sprintf(format, args...)
		return result
	}

	tags, err := parseTags(field.Value)
	if err != nil {
		return fail(ResultPermError, "signature illisible : %v", err)
	}
	result.Domain = strings.ToLower(tags["d"])
	result.Selector = tags["s"]
	result.Algorithm = strings.ToLower(tags["a"])
	for _, required := range []string{"v", "a", "b", "bh", "d", "h", "s"} {
		if _, ok := tags[required]; !ok {
			return fail(ResultPermError, "paramètre %s= manquant", required)
		}
	}
	if tags["v"] != "1" {
		return fail(ResultPermError, "version %q non supportée", tags["v"])
	}
	for _, name := range strings.Split(tags["h"], ":") {
		if name = strings.TrimSpace(name); name != "" {
			result.Headers = append(result.Headers, name)
		}
	}
	headerCanon, bodyCanon := "simple", "simple"
	if c, ok := tags["c"]; ok {
		headerCanon, bodyCanon, _ = strings.Cut(strings.ToLower(c), "/")
		if bodyCanon == "" {
			bodyCanon = "simple"
		}
	}
	canonOK := (headerCanon == "simple" || headerCanon == "relaxed") && (bodyCanon == "simple" || bodyCanon == "relaxed")
	if canonOK {
		result.HeaderCanon, result.BodyCanon = headerCanon, bodyCanon
	}
	// Fields hashed, selected from the bottom (RFC 6376 §5.4.2); filled
	// before any check so that the details are shown whatever the result.
	used := map[int]bool{}
	for _, name := range result.Headers {
		signed := SignedField{Name: name, Index: -1}
		for i := len(m.Fields) - 1; i >= 0; i-- {
			if !used[i] && strings.EqualFold(m.Fields[i].Name, name) {
				used[i] = true
				signed.Index, signed.Raw = i, m.Fields[i].Raw
				if canonOK {
					signed.Canonical = canonicalHeader(signed.Raw, headerCanon)
				}
				break
			}
		}
		result.Fields = append(result.Fields, signed)
	}
	if canonOK {
		result.SignatureInput = strings.TrimSuffix(canonicalHeader(removeSignatureValue(field.Raw), headerCanon), "\r\n")
	}

	signsFrom := false
	for _, name := range result.Headers {
		signsFrom = signsFrom || strings.EqualFold(name, "from")
	}
	if !signsFrom {
		return fail(ResultPermError, "l'en-tête From n'est pas signé")
	}
	if identity, ok := tags["i"]; ok {
		if d := domainOf(identity); d != result.Domain && !strings.HasSuffix(d, "."+result.Domain) {
			return fail(ResultPermError, "identité i=%s hors du domaine d=%s", identity, result.Domain)
		}
	}
	if t, err := strconv.ParseInt(tags["t"], 10, 64); err == nil {
		result.Signed = time.Unix(t, 0)
	}

	var newHash func() hash.Hash
	var cryptoHash crypto.Hash
	keyType := "rsa"
	switch result.Algorithm {
	case "rsa-sha256":
		newHash, cryptoHash = sha256.New, crypto.SHA256
	case "ed25519-sha256":
		newHash, cryptoHash, keyType = sha256.New, crypto.SHA256, "ed25519"
	case "rsa-sha1":
		return fail(ResultPermError, "algorithme rsa-sha1 refusé, considéré comme non sûr (RFC 8301)")
	default:
		return fail(ResultPermError, "algorithme %q non supporté", result.Algorithm)
	}

	if !canonOK {
		return fail(ResultPermError, "canonicalisation %q non supportée", tags["c"])
	}

	// Body hash: a mismatch does not stop the verification, the headers
	// are checked too to tell what was modified.
	body := canonicalBody(m.Body, bodyCanon)
	if l, ok := tags["l"]; ok {
		limit, err := strconv.Atoi(l)
		if err != nil || limit < 0 {
			return fail(ResultPermError, "longueur l=%s invalide", l)
		}
		if limit > len(body) {
			return fail(ResultFail, "le corps est plus court que la longueur signée")
		}
		body = body[:limit]
		result.BodyLimit = true
	}
	bodyHash := newHash()
	bodyHash.Write(body)
	expected, err := base64.StdEncoding.DecodeString(tags["bh"])
	if err != nil {
		return fail(ResultPermError, "empreinte bh= illisible")
	}
	computed := bodyHash.Sum(nil)
	result.BodyHashComputed = base64.StdEncoding.EncodeToString(computed)
	result.BodyLength = len(body)
	result.BodyHash = "ok"
	if !bytes.Equal(computed, expected) {
		result.BodyHash = "différent"
		result.BodyHint = bodyHint(m.Body, bodyCanon, expected, newHash)
	}
	bodyFailed := func(headers string) DKIMResult {
		return fail(ResultFail, "le corps du mail a été modifié depuis la signature%s", headers)
	}

	// Public key: without it, a modified body still makes the result fail.
	keyFail := func(status, format string, args ...any) DKIMResult {
		if result.BodyHash != "ok" {
			return bodyFailed(" (en-têtes non vérifiés : " + fmt.Sprintf(format, args...) + ")")
		}
		return fail(status, format, args...)
	}
	key, err := lookupKey(ctx, resolver, result.Selector, result.Domain)
	if err != nil {
		if e, ok := err.(*spfError); ok {
			return keyFail(e.result, "%s", e.reason)
		}
		return keyFail(ResultTempError, "%v", err)
	}
	result.Testing = key.testing
	if key.keyType != keyType {
		return keyFail(ResultPermError, "clé de type %s pour une signature %s", key.keyType, result.Algorithm)
	}
	if len(key.hashes) > 0 && !contains(key.hashes, "sha256") {
		return keyFail(ResultPermError, "la clé n'autorise pas sha256")
	}

	// Header hash
	signature, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		return fail(ResultPermError, "signature b= illisible")
	}
	verify := func(fields []string) bool {
		h := newHash()
		for _, f := range fields {
			h.Write([]byte(f))
		}
		h.Write([]byte(result.SignatureInput))
		digest := h.Sum(nil)
		switch k := key.key.(type) {
		case *rsa.PublicKey:
			return rsa.VerifyPKCS1v15(k, cryptoHash, digest, signature) == nil
		case ed25519.PublicKey:
			return ed25519.Verify(k, digest, signature)
		}
		return false
	}
	switch k := key.key.(type) {
	case *rsa.PublicKey:
		result.KeyBits = k.N.BitLen()
		if result.KeyBits < 1024 {
			return keyFail(ResultPermError, "clé RSA de %d bits, trop courte (RFC 8301)", result.KeyBits)
		}
	case ed25519.PublicKey:
		result.KeyBits = 256
	}
	canonical := make([]string, len(result.Fields))
	for i, f := range result.Fields {
		canonical[i] = f.Canonical
	}
	if !verify(canonical) {
		result.HeaderHash = "différent"
		result.HeaderHint = findModifiedField(m, &result, canonical, headerCanon, verify)
		if result.BodyHash != "ok" {
			return bodyFailed(", et les en-têtes signés aussi")
		}
		if result.HeaderHint != "" {
			return fail(ResultFail, "signature invalide : %s", result.HeaderHint)
		}
		return fail(ResultFail, "signature invalide : en-têtes modifiés, ou clé changée depuis l'envoi")
	}
	result.HeaderHash = "ok"
	if result.BodyHash != "ok" {
		return bodyFailed(" (les en-têtes signés sont intacts)")
	}

	if x, err := strconv.ParseInt(tags["x"], 10, 64); err == nil && time.Now().After(time.Unix(x, 0)) {
		return fail(ResultFail, "signature valide mais expirée depuis le %s", time.Unix(x, 0).Format("02.01.2006 15:04"))
	}
	result.Result = ResultPass
	if result.Testing {
		result.Reason = "clé publiée en mode test (t=y)"
	}
	return result
}

// subjectPrefix matches the tags added in front of a subject by gateways
// and mail clients: "[EXT] ", "***SPAM*** ", "RE: "...
var subjectPrefix = regexp.MustCompile(`^\s*(?:\[[^\]]{1,40}\]|\*{1,5}[^*]{1,30}\*{1,5}|\((?:EXT|EXTERNAL|SPAM)\)|(?i:RE|TR|FW|FWD|AW|WG|RV|SV|VS)\s*:)\s*`)

// findModifiedField looks for the header field whose change breaks the
// signature, by verifying it with the field as it probably was: absent
// (added since), another occurrence (a duplicate was added), or a subject
// without the prefixes added on the way. It marks the field found and
// returns a description, or "" when no single change explains the failure.
func findModifiedField(m Message, result *DKIMResult, canonical []string, canon string, verify func([]string) bool) string {
	try := func(k int, value string) bool {
		saved := canonical[k]
		canonical[k] = value
		ok := verify(canonical)
		canonical[k] = saved
		return ok
	}
	for k := range result.Fields {
		f := &result.Fields[k]
		if f.Index < 0 {
			continue
		}
		if try(k, "") {
			f.Modified, f.Note = true, "champ ajouté après la signature : il n'existait pas quand le mail a été signé"
			return fmt.Sprintf("le champ %s a été ajouté après la signature", m.Fields[f.Index].Name)
		}
		for j, other := range m.Fields {
			if j != f.Index && strings.EqualFold(other.Name, f.Name) && try(k, canonicalHeader(other.Raw, canon)) {
				f.Modified, f.Note = true, fmt.Sprintf("un champ %s a été ajouté : la signature porte sur une autre occurrence", other.Name)
				return fmt.Sprintf("un second champ %s a été ajouté après la signature", other.Name)
			}
		}
		if strings.EqualFold(f.Name, "subject") {
			name, value, _ := strings.Cut(f.Raw, ":")
			value = strings.TrimSpace(unfold(value))
			for subjectPrefix.MatchString(value) {
				value = subjectPrefix.ReplaceAllString(value, "")
				if try(k, canonicalHeader(name+": "+value+"\r\n", canon)) {
					f.Modified, f.Note = true, fmt.Sprintf("sujet modifié, sujet d'origine : « %s »", strings.Join(strings.Fields(value), " "))
					return "un préfixe a été ajouté au sujet"
				}
			}
		}
	}
	return ""
}

// bodyHint looks for the change that explains a body hash mismatch, by
// hashing variants of the body.
func bodyHint(body []byte, canon string, expected []byte, newHash func() hash.Hash) string {
	matches := func(b []byte) bool {
		h := newHash()
		h.Write(b)
		return bytes.Equal(h.Sum(nil), expected)
	}
	other := map[string]string{"simple": "relaxed", "relaxed": "simple"}[canon]
	switch {
	case matches(bytes.ReplaceAll(canonicalBody(body, canon), []byte("\r\n"), []byte("\n"))):
		return "l'empreinte correspond au corps avec des fins de ligne LF au lieu de CRLF : le signataire n'a pas respecté la RFC 6376, le contenu n'a pas été modifié"
	case matches(canonicalBody(body, other)):
		return "l'empreinte correspond à la canonicalisation " + other + " au lieu de " + canon + " : erreur du signataire, le contenu n'a pas été modifié"
	}
	return ""
}

type dkimKey struct {
	keyType string
	key     any
	hashes  []string
	testing bool
}

func lookupKey(ctx context.Context, resolver Resolver, selector, domain string) (*dkimKey, error) {
	name := selector + "._domainkey." + domain
	txts, err := resolver.LookupTXT(ctx, name)
	if isNotFound(err) || (err == nil && len(txts) == 0) {
		return nil, permError("clé publique introuvable (%s)", name)
	}
	if err != nil {
		return nil, tempError("requête DNS %s : %v", name, err)
	}

	tags, err := parseTags(txts[0])
	if err != nil {
		return nil, permError("clé publique illisible : %v", err)
	}
	if v, ok := tags["v"]; ok && v != "DKIM1" {
		return nil, permError("version de clé %q non supportée", v)
	}
	key := &dkimKey{keyType: strings.ToLower(tags["k"])}
	if key.keyType == "" {
		key.keyType = "rsa"
	}
	if h, ok := tags["h"]; ok {
		key.hashes = strings.Split(strings.ToLower(h), ":")
	}
	key.testing = contains(strings.Split(tags["t"], ":"), "y")

	p := tags["p"]
	if p == "" {
		return nil, permError("clé révoquée par le domaine (p= vide)")
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, permError("clé publique illisible (base64)")
	}
	switch key.keyType {
	case "rsa":
		if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
			if rsaKey, ok := parsed.(*rsa.PublicKey); ok {
				key.key = rsaKey
				return key, nil
			}
		}
		if rsaKey, err := x509.ParsePKCS1PublicKey(der); err == nil {
			key.key = rsaKey
			return key, nil
		}
		return nil, permError("clé RSA illisible")
	case "ed25519":
		if len(der) != ed25519.PublicKeySize {
			return nil, permError("clé Ed25519 de taille invalide")
		}
		key.key = ed25519.PublicKey(der)
		return key, nil
	}
	return nil, permError("type de clé %q non supporté", key.keyType)
}

// parseTags parses a DKIM tag-list (RFC 6376 §3.2). Whitespace is removed
// from the values, as required for base64 values and harmless for others.
func parseTags(s string) (map[string]string, error) {
	tags := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("paramètre sans valeur « %s »", strings.TrimSpace(part))
		}
		name = strings.TrimSpace(name)
		if _, dup := tags[name]; dup {
			return nil, fmt.Errorf("paramètre %s= répété", name)
		}
		tags[name] = strings.Join(strings.Fields(value), "")
	}
	return tags, nil
}

var (
	wsp         = regexp.MustCompile(`[ \t]+`)
	trailingWSP = regexp.MustCompile(`[ \t]+\r\n`)
)

// canonicalHeader canonicalizes a raw header field, CRLF included
// (RFC 6376 §3.4.1, §3.4.2).
func canonicalHeader(raw, canon string) string {
	if canon == "simple" {
		return raw
	}
	name, value, _ := strings.Cut(raw, ":")
	value = unfold(value)
	value = strings.Trim(wsp.ReplaceAllString(value, " "), " ")
	return strings.ToLower(strings.TrimSpace(name)) + ":" + value + "\r\n"
}

// canonicalBody canonicalizes a CRLF body (RFC 6376 §3.4.3, §3.4.4).
func canonicalBody(body []byte, canon string) []byte {
	if canon == "relaxed" {
		body = trailingWSP.ReplaceAll(body, []byte("\r\n"))
		body = wsp.ReplaceAll(body, []byte(" "))
		// A last line without CRLF also loses its trailing spaces.
		body = bytes.TrimRight(body, " \t")
	}
	for bytes.HasSuffix(body, []byte("\r\n\r\n")) {
		body = body[:len(body)-2]
	}
	if len(body) == 0 {
		if canon == "relaxed" {
			return nil
		}
		return []byte("\r\n")
	}
	if bytes.Equal(body, []byte("\r\n")) && canon == "relaxed" {
		return nil
	}
	if !bytes.HasSuffix(body, []byte("\r\n")) {
		body = append(body, '\r', '\n')
	}
	return body
}

// removeSignatureValue empties the b= tag of a raw DKIM-Signature field,
// keeping everything else byte for byte (RFC 6376 §3.7).
func removeSignatureValue(raw string) string {
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return raw
	}
	var b strings.Builder
	b.WriteString(raw[:colon+1])
	parts := strings.Split(raw[colon+1:], ";")
	for i, part := range parts {
		if i > 0 {
			b.WriteByte(';')
		}
		name, _, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(name) == "b" {
			b.WriteString(name + "=")
			if i == len(parts)-1 && strings.HasSuffix(part, "\r\n") {
				b.WriteString("\r\n")
			}
			continue
		}
		b.WriteString(part)
	}
	return b.String()
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if strings.TrimSpace(item) == s {
			return true
		}
	}
	return false
}
