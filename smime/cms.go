package smime

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CMS object identifiers (RFC 5652, RFC 8551).
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidAuthEnveloped = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContent     encapsulatedContent
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContent struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// parsed is a SignedData ready to verify.
type parsed struct {
	certificates []*x509.Certificate
	signers      []signerInfo
	// content is the encapsulated content (opaque signatures), nil for a
	// detached signature.
	content []byte
}

// errEncrypted reports an encrypted message: only its recipient can read
// it.
var errEncrypted = errors.New("message chiffré")

// parse reads a CMS ContentInfo holding a SignedData.
func parse(ber []byte) (*parsed, error) {
	der, err := berToDER(ber)
	if err != nil {
		return nil, err
	}
	var info contentInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("structure CMS illisible : %w", err)
	}
	switch {
	case info.ContentType.Equal(oidEnvelopedData), info.ContentType.Equal(oidAuthEnveloped):
		return nil, errEncrypted
	case !info.ContentType.Equal(oidSignedData):
		return nil, fmt.Errorf("type de contenu CMS %v non supporté", info.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(info.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData illisible : %w", err)
	}
	p := &parsed{signers: sd.SignerInfos}
	// eContent [0] EXPLICIT OCTET STRING
	// (encoding/asn1 keeps the [0] wrapper in a RawValue).
	if c := sd.EncapContent.Content; len(c.FullBytes) > 0 {
		var data []byte
		if _, err := asn1.Unmarshal(c.Bytes, &data); err != nil {
			return nil, fmt.Errorf("contenu signé illisible : %w", err)
		}
		p.content = data
	}
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return nil, fmt.Errorf("certificats illisibles : %w", err)
		}
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			continue // attribute certificates and other formats
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		p.certificates = append(p.certificates, cert)
	}
	if len(p.signers) == 0 {
		return nil, errors.New("aucun signataire")
	}
	return p, nil
}

// signerCertificate finds the certificate of a signer among those of the
// message.
func (p *parsed) signerCertificate(s signerInfo) *x509.Certificate {
	if s.SID.Class == asn1.ClassContextSpecific && s.SID.Tag == 0 {
		// subjectKeyIdentifier
		for _, c := range p.certificates {
			if string(c.SubjectKeyId) == string(s.SID.Bytes) {
				return c
			}
		}
		return nil
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(s.SID.FullBytes, &ias); err != nil {
		return nil
	}
	for _, c := range p.certificates {
		if c.SerialNumber.Cmp(ias.Serial) == 0 && string(c.RawIssuer) == string(ias.Issuer.FullBytes) {
			return c
		}
	}
	return nil
}

// signedAttributes returns the attributes and the bytes signed: the DER
// encoding of the attributes as a SET (RFC 5652 §5.4).
func signedAttributes(s signerInfo) ([]attribute, []byte, error) {
	if len(s.SignedAttrs.FullBytes) == 0 {
		return nil, nil, nil
	}
	signed := append([]byte{}, s.SignedAttrs.FullBytes...)
	signed[0] = 0x31 // [0] IMPLICIT → SET OF
	var attrs []attribute
	rest := s.SignedAttrs.Bytes
	for len(rest) > 0 {
		var a attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, nil, fmt.Errorf("attributs signés illisibles : %w", err)
		}
		attrs = append(attrs, a)
	}
	return attrs, signed, nil
}

// attributeValue returns the first value of an attribute.
func attributeValue(attrs []attribute, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			return a.Values.Bytes, true
		}
	}
	return nil, false
}

func signingTime(attrs []attribute) time.Time {
	raw, ok := attributeValue(attrs, oidSigningTime)
	if !ok {
		return time.Time{}
	}
	var t time.Time
	if _, err := asn1.Unmarshal(raw, &t); err != nil {
		return time.Time{}
	}
	return t
}
