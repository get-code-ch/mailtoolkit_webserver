// Package smime verifies the S/MIME signature of a mail (RFC 8551, CMS RFC
// 5652): integrity of the signed content, signature, certificate chain,
// revocation (OCSP, CRL), and the identity certified for the signer.
package smime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Status of a signature.
const (
	StatusNone      = "none"      // not signed
	StatusValid     = "valid"     // signature and certificate valid
	StatusInvalid   = "invalid"   // content modified or signature wrong
	StatusUntrusted = "untrusted" // signature right, certificate not trusted
	StatusEncrypted = "encrypted" // encrypted, only the recipient can read it
	StatusError     = "error"     // unreadable
)

// Result is the verification of the S/MIME signature of a mail.
type Result struct {
	Status string
	Reason string
	// Opaque is set for a signature enclosing its content
	// (application/pkcs7-mime), which mail readers must unpack.
	Opaque bool

	Signer             *Certificate
	Chain              []*Certificate
	ChainError         string
	SigningTime        time.Time
	DigestAlgorithm    string
	SignatureAlgorithm string
	// Integrity is "ok" when the content matches the signed digest,
	// "différent" when it was modified.
	Integrity  string
	Revocation Revocation
	// FromMatch tells whether the certificate is issued for the From
	// address of the mail.
	FromMatch bool
	From      string
}

// Trusted reports whether the signature proves the From address: valid,
// trusted certificate for that address, not revoked.
func (r Result) Trusted() bool {
	return r.Status == StatusValid && r.FromMatch && r.Revocation.Status != RevocationRevoked
}

// Certificate describes a certificate for the page.
type Certificate struct {
	Subject      string
	Emails       []string
	Organization string
	// OrganizationID is the registration number of the organization
	// (organizationIdentifier, e.g. NTRCH-CHE-109.030.864).
	OrganizationID string
	Pseudonym      string
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
	// Validation is the level of the CA/Browser Forum S/MIME policy:
	// mailbox, organization, sponsor, individual, or "" when unknown.
	Validation string
	cert       *x509.Certificate
}

// ValidationText explains the level of a certificate.
func (c *Certificate) ValidationText() string {
	switch c.Validation {
	case "mailbox":
		return "adresse vérifiée seulement (le titulaire contrôle la boîte mail)"
	case "organization":
		return "organisation vérifiée par l'autorité de certification"
	case "sponsor":
		return "organisation vérifiée, et personne ou service attesté par l'organisation"
	case "individual":
		return "identité de la personne vérifiée par l'autorité de certification"
	}
	return "niveau de vérification non indiqué"
}

// IdentityVerified reports whether more than the mailbox was checked.
func (c *Certificate) IdentityVerified() bool {
	return c.Validation == "organization" || c.Validation == "sponsor" || c.Validation == "individual"
}

// Verifier verifies S/MIME signatures.
type Verifier struct {
	// Roots are the trusted certification authorities, the system ones
	// when nil.
	Roots *x509.CertPool
	// Revocation checks the signer certificate, nil to skip.
	Revocation *RevocationChecker
	Now        func() time.Time
}

// Verify checks the S/MIME signature of a raw mail sent by from.
func (v *Verifier) Verify(ctx context.Context, raw []byte, from string) Result {
	r := Result{Status: StatusNone, From: from}
	sig, err := findSignature(raw)
	if errors.Is(err, errNotSigned) {
		return r
	}
	fail := func(status, format string, args ...any) Result {
		r.Status, r.Reason = status, fmt.Sprintf(format, args...)
		return r
	}
	if err != nil {
		return fail(StatusError, "%v", err)
	}
	r.Opaque = sig.opaque
	p, err := parse(sig.cms)
	if errors.Is(err, errEncrypted) {
		return fail(StatusEncrypted, "message chiffré pour son destinataire : son contenu et l'éventuelle signature qu'il contient ne sont pas lisibles")
	}
	if err != nil {
		return fail(StatusError, "%v", err)
	}
	content := sig.content
	if sig.opaque {
		content = p.content
	}
	if content == nil {
		return fail(StatusError, "signature sans contenu signé")
	}

	s := p.signers[0]
	cert := p.signerCertificate(s)
	if cert == nil {
		return fail(StatusError, "le certificat du signataire n'est pas joint à la signature")
	}
	r.Signer = describe(cert)
	r.FromMatch = slices.ContainsFunc(cert.EmailAddresses, func(e string) bool { return strings.EqualFold(e, from) })

	hash, digestName, ok := digestAlgorithm(s.DigestAlgorithm.Algorithm)
	r.DigestAlgorithm = digestName
	if !ok {
		return fail(StatusError, "algorithme d'empreinte %v non supporté", s.DigestAlgorithm.Algorithm)
	}

	// Integrity: the digest of the content, signed in the attributes.
	attrs, signed, err := signedAttributes(s)
	if err != nil {
		return fail(StatusError, "%v", err)
	}
	h := hash.New()
	h.Write(content)
	digest := h.Sum(nil)
	if signed != nil {
		raw, ok := attributeValue(attrs, oidMessageDigest)
		var expected []byte
		if ok {
			_, err = asn1.Unmarshal(raw, &expected)
		}
		if !ok || err != nil {
			return fail(StatusError, "empreinte du contenu absente des attributs signés")
		}
		r.SigningTime = signingTime(attrs)
		r.Integrity = "ok"
		if !bytes.Equal(digest, expected) {
			r.Integrity = "différent"
		}
	} else {
		signed = content // signature directly on the content
	}

	// Signature with the key of the certificate.
	algorithm, name, err := signatureAlgorithm(s.SignatureAlgorithm.Algorithm, s.DigestAlgorithm.Algorithm)
	r.SignatureAlgorithm = name
	if err != nil {
		return fail(StatusError, "%v", err)
	}
	if err := cert.CheckSignature(algorithm, signed, s.Signature); err != nil {
		var insecure x509.InsecureAlgorithmError
		if errors.As(err, &insecure) {
			return fail(StatusInvalid, "algorithme %s refusé, considéré comme non sûr", name)
		}
		return fail(StatusInvalid, "signature invalide : elle ne correspond pas au certificat")
	}
	if r.Integrity == "différent" {
		return fail(StatusInvalid, "le contenu a été modifié depuis la signature (ou réencodé lors d'un transfert ou d'un export)")
	}

	// Certificate chain, at the signing time when known.
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	at := now
	if !r.SigningTime.IsZero() && r.SigningTime.Before(now) {
		at = r.SigningTime
	}
	intermediates := x509.NewCertPool()
	for _, c := range p.certificates {
		if c != cert {
			intermediates.AddCert(c)
		}
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	if err != nil {
		r.ChainError = chainError(err)
	} else {
		for _, c := range chains[0] {
			r.Chain = append(r.Chain, describe(c))
		}
		if v.Revocation != nil && len(chains[0]) > 1 {
			r.Revocation = v.Revocation.Check(ctx, cert, chains[0][1])
		}
	}

	switch {
	case r.ChainError != "":
		return fail(StatusUntrusted, "signature correcte, mais certificat non reconnu : %s", r.ChainError)
	case r.Revocation.Status == RevocationRevoked:
		r.Status = StatusValid
		r.Reason = "signature correcte, mais certificat révoqué par l'autorité de certification" + r.Revocation.when()
	case !r.FromMatch:
		r.Status = StatusValid
		r.Reason = fmt.Sprintf("signature valide, mais le certificat est délivré pour %s et non pour l'expéditeur %s",
			strings.Join(cert.EmailAddresses, ", "), from)
	default:
		r.Status = StatusValid
		r.Reason = "signature valide : le contenu n'a pas été modifié depuis la signature de " + from
	}
	if !now.Before(cert.NotAfter) && r.Status == StatusValid {
		r.Reason += fmt.Sprintf(" ; le certificat a expiré le %s, après la signature", cert.NotAfter.Local().Format("02.01.2006"))
	}
	return r
}

func chainError(err error) string {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknown):
		return "autorité de certification inconnue (certificat auto-signé ou chaîne incomplète)"
	case errors.As(err, &invalid):
		switch invalid.Reason {
		case x509.Expired:
			return "certificat expiré ou pas encore valide à la date de signature"
		case x509.IncompatibleUsage:
			return "certificat non autorisé pour la signature de mails"
		}
	}
	return err.Error()
}

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidRSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidRSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSAPSS      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
)

func digestAlgorithm(oid asn1.ObjectIdentifier) (crypto.Hash, string, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, "SHA-256", true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, "SHA-384", true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, "SHA-512", true
	case oid.Equal(oidSHA1):
		return crypto.SHA1, "SHA-1", true
	}
	return 0, oid.String(), false
}

// signatureAlgorithm maps the CMS algorithms (signature, digest) to the
// x509 one; CMS often writes rsaEncryption and gives the digest apart.
func signatureAlgorithm(sig, digest asn1.ObjectIdentifier) (x509.SignatureAlgorithm, string, error) {
	_, digestName, _ := digestAlgorithm(digest)
	byDigest := func(rsa1, rsa256, rsa384, rsa512 x509.SignatureAlgorithm, prefix string) (x509.SignatureAlgorithm, string, error) {
		name := prefix + " " + digestName
		switch {
		case digest.Equal(oidSHA256):
			return rsa256, name, nil
		case digest.Equal(oidSHA384):
			return rsa384, name, nil
		case digest.Equal(oidSHA512):
			return rsa512, name, nil
		case digest.Equal(oidSHA1) && rsa1 != x509.UnknownSignatureAlgorithm:
			return rsa1, name, nil
		}
		return x509.UnknownSignatureAlgorithm, name, fmt.Errorf("algorithme de signature %s non supporté", name)
	}
	switch {
	case sig.Equal(oidRSA), sig.Equal(oidRSASHA1), sig.Equal(oidRSASHA256), sig.Equal(oidRSASHA384), sig.Equal(oidRSASHA512):
		return byDigest(x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, "RSA")
	case sig.Equal(oidRSAPSS):
		return byDigest(x509.UnknownSignatureAlgorithm, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, "RSA-PSS")
	case sig.Equal(oidECPublicKey), sig.Equal(oidECDSASHA256), sig.Equal(oidECDSASHA384), sig.Equal(oidECDSASHA512):
		return byDigest(x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, "ECDSA")
	case sig.Equal(oidEd25519):
		return x509.PureEd25519, "Ed25519", nil
	}
	return x509.UnknownSignatureAlgorithm, sig.String(), fmt.Errorf("algorithme de signature %v non supporté", sig)
}

var (
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	oidPseudonym              = asn1.ObjectIdentifier{2, 5, 4, 65}
	// CA/Browser Forum S/MIME Baseline Requirements: 2.23.140.1.5.<level>.<generation>
	oidCABFSMIME = asn1.ObjectIdentifier{2, 23, 140, 1, 5}
)

func describe(cert *x509.Certificate) *Certificate {
	c := &Certificate{
		Subject:   cert.Subject.CommonName,
		Emails:    cert.EmailAddresses,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		cert:      cert,
	}
	if len(cert.Subject.Organization) > 0 {
		c.Organization = cert.Subject.Organization[0]
	}
	for _, n := range cert.Subject.Names {
		value, _ := n.Value.(string)
		switch {
		case n.Type.Equal(oidOrganizationIdentifier):
			c.OrganizationID = value
		case n.Type.Equal(oidPseudonym):
			c.Pseudonym = value
		}
	}
	for _, policy := range cert.PolicyIdentifiers {
		if len(policy) == 7 && slices.Equal(policy[:5], oidCABFSMIME) {
			c.Validation = map[int]string{1: "mailbox", 2: "organization", 3: "sponsor", 4: "individual"}[policy[5]]
		}
	}
	return c
}
