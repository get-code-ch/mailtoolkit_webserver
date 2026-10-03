package smime

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Revocation statuses.
const (
	RevocationGood    = "good"
	RevocationRevoked = "revoked"
	RevocationUnknown = "unknown"
)

// Revocation is the revocation status of the signer certificate.
type Revocation struct {
	// Status is empty when not checked.
	Status    string
	Method    string // OCSP or CRL
	Source    string
	RevokedAt time.Time
	Reason    string
	Error     string
}

// When formats the revocation date for the page.
func (r Revocation) When() string {
	return r.when()
}

func (r Revocation) when() string {
	if r.RevokedAt.IsZero() {
		return ""
	}
	return " le " + r.RevokedAt.Local().Format("02.01.2006")
}

// maxRevocationResponse bounds an OCSP response or a CRL.
const maxRevocationResponse = 20 << 20

// RevocationChecker asks the certification authority whether a certificate
// was revoked: OCSP first, the CRL otherwise. Answers are cached until
// their next update.
type RevocationChecker struct {
	Client *http.Client

	mu    sync.Mutex
	cache map[string]cachedRevocation
}

type cachedRevocation struct {
	revocation Revocation
	until      time.Time
}

func NewRevocationChecker() *RevocationChecker {
	return &RevocationChecker{
		Client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("trop de redirections")
				}
				return nil
			},
		},
		cache: map[string]cachedRevocation{},
	}
}

// Check returns the revocation status of cert, issued by issuer.
func (c *RevocationChecker) Check(ctx context.Context, cert, issuer *x509.Certificate) Revocation {
	key := string(issuer.RawSubject) + "/" + cert.SerialNumber.String()
	c.mu.Lock()
	if cached, ok := c.cache[key]; ok && time.Now().Before(cached.until) {
		c.mu.Unlock()
		return cached.revocation
	}
	c.mu.Unlock()

	var errs []string
	for _, server := range cert.OCSPServer {
		r, until, err := c.ocsp(ctx, server, cert, issuer)
		if err == nil {
			c.store(key, r, until)
			return r
		}
		errs = append(errs, fmt.Sprintf("OCSP %s : %v", server, err))
	}
	for _, point := range cert.CRLDistributionPoints {
		r, until, err := c.crl(ctx, point, cert, issuer)
		if err == nil {
			c.store(key, r, until)
			return r
		}
		errs = append(errs, fmt.Sprintf("CRL %s : %v", point, err))
	}
	r := Revocation{Status: RevocationUnknown, Error: "aucun service de révocation n'a répondu"}
	if len(errs) > 0 {
		r.Error = strings.Join(errs, " ; ")
	}
	if len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		r.Error = "le certificat n'indique aucun service de révocation"
	}
	c.store(key, r, time.Now().Add(10*time.Minute))
	return r
}

func (c *RevocationChecker) store(key string, r Revocation, until time.Time) {
	if max := time.Now().Add(24 * time.Hour); until.After(max) || until.IsZero() {
		until = max
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) > 10000 {
		clear(c.cache)
	}
	c.cache[key] = cachedRevocation{r, until}
}

func (c *RevocationChecker) ocsp(ctx context.Context, server string, cert, issuer *x509.Certificate) (Revocation, time.Time, error) {
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return Revocation{}, time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(request))
	if err != nil {
		return Revocation{}, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	data, err := c.fetch(req)
	if err != nil {
		return Revocation{}, time.Time{}, err
	}
	resp, err := ocsp.ParseResponseForCert(data, cert, issuer)
	if err != nil {
		return Revocation{}, time.Time{}, fmt.Errorf("réponse illisible : %w", err)
	}
	r := Revocation{Method: "OCSP", Source: server}
	switch resp.Status {
	case ocsp.Good:
		r.Status = RevocationGood
	case ocsp.Revoked:
		r.Status, r.RevokedAt, r.Reason = RevocationRevoked, resp.RevokedAt, reasonText(resp.RevocationReason)
	default:
		r.Status = RevocationUnknown
		r.Error = "certificat inconnu du service OCSP"
	}
	return r, resp.NextUpdate, nil
}

func (c *RevocationChecker) crl(ctx context.Context, point string, cert, issuer *x509.Certificate) (Revocation, time.Time, error) {
	if !strings.HasPrefix(point, "http://") && !strings.HasPrefix(point, "https://") {
		return Revocation{}, time.Time{}, errors.New("adresse non supportée")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, point, nil)
	if err != nil {
		return Revocation{}, time.Time{}, err
	}
	data, err := c.fetch(req)
	if err != nil {
		return Revocation{}, time.Time{}, err
	}
	list, err := x509.ParseRevocationList(data)
	if err != nil {
		return Revocation{}, time.Time{}, fmt.Errorf("liste illisible : %w", err)
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return Revocation{}, time.Time{}, errors.New("liste non signée par l'autorité du certificat")
	}
	r := Revocation{Status: RevocationGood, Method: "CRL", Source: point}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			r.Status, r.RevokedAt, r.Reason = RevocationRevoked, entry.RevocationTime, reasonText(entry.ReasonCode)
			break
		}
	}
	return r, list.NextUpdate, nil
}

func (c *RevocationChecker) fetch(req *http.Request) ([]byte, error) {
	req.Header.Set("User-Agent", "mailtoolkit_webserver (mail analysis)")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("réponse %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRevocationResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRevocationResponse {
		return nil, errors.New("réponse trop volumineuse")
	}
	return data, nil
}

// reasonText explains a revocation reason (RFC 5280 §5.3.1).
func reasonText(code int) string {
	return map[int]string{
		1: "clé privée compromise", 2: "autorité de certification compromise", 3: "changement d'affiliation",
		4: "certificat remplacé", 5: "cessation d'activité", 6: "certificat suspendu",
		9: "privilège retiré", 10: "attribut compromis",
	}[code]
}
