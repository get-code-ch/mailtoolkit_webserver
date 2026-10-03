package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// ReputationConfig sets the external reputation checks: DNS blocklists for
// the IP addresses and domains of a mail, and the age of its domains
// through RDAP. The checked addresses and domains are sent to these
// services.
type ReputationConfig struct {
	Disabled bool `json:"disabled"`
	// IPLists and DomainLists are DNS blocklist zones; defaults are used
	// when empty.
	IPLists     []string `json:"dnsbl_ip"`
	DomainLists []string `json:"dnsbl_domain"`
	// SpamhausDQSKey uses the Spamhaus Data Query Service, required when
	// the server resolves through a public DNS resolver. The
	// MTK_SPAMHAUS_DQS_KEY environment variable overrides it.
	SpamhausDQSKey string `json:"spamhaus_dqs_key"`
	RDAPDisabled   bool   `json:"rdap_disabled"`
	// RevocationDisabled skips the OCSP and CRL queries of the S/MIME
	// certificates.
	RevocationDisabled bool `json:"revocation_disabled"`
}

var (
	defaultIPLists     = []string{"zen.spamhaus.org", "bl.spamcop.net"}
	defaultDomainLists = []string{"dbl.spamhaus.org", "multi.surbl.org"}
)

// zones returns the blocklist zones, through DQS when a key is set.
func (c ReputationConfig) zones() (ip, domain []string) {
	ip, domain = c.IPLists, c.DomainLists
	if len(ip) == 0 {
		ip = defaultIPLists
	}
	if len(domain) == 0 {
		domain = defaultDomainLists
	}
	if c.SpamhausDQSKey == "" {
		return ip, domain
	}
	dqs := func(zones []string) []string {
		out := make([]string, len(zones))
		for i, z := range zones {
			if name, ok := strings.CutSuffix(z, ".spamhaus.org"); ok {
				z = c.SpamhausDQSKey + "." + name + ".dq.spamhaus.net"
			}
			out[i] = z
		}
		return out
	}
	return dqs(ip), dqs(domain)
}

// reputation is what the external services say about the IP addresses and
// domains of a mail.
type reputation struct {
	Listings []listing
	// Errors are the lists that could not answer (public resolver refused,
	// quota): their silence does not mean "not listed".
	Errors  []string
	Domains []domainAge
	Checked int
}

// listing is an IP address or a domain found in a blocklist.
type listing struct {
	Subject string
	// Role tells where the subject comes from: "serveur d'envoi", "From",
	// "lien"...
	Role    string
	List    string
	Code    string
	Meaning string
	Level   string
}

// domainAge is the registration date of a domain, from RDAP.
type domainAge struct {
	Domain     string
	Role       string
	Registered time.Time
	Error      string
}

// Days is the age of the domain in days.
func (d domainAge) Days() int {
	return int(time.Since(d.Registered).Hours() / 24)
}

// Level rates the age: a domain registered a few days before the mail is
// typical of phishing.
func (d domainAge) Level() string {
	switch {
	case d.Registered.IsZero():
		return ""
	case d.Days() < 30:
		return levelDanger
	case d.Days() < 180:
		return levelWarning
	}
	return "ok"
}

func (d domainAge) DateText() string {
	if d.Registered.IsZero() {
		return ""
	}
	return d.Registered.Format("02.01.2006")
}

// subject is an IP address or a domain to check, with its role in the mail.
type subject struct {
	Value string
	Role  string
}

// reputationChecker queries the blocklists and the RDAP servers.
type reputationChecker struct {
	resolver    mailauth.Resolver
	ipLists     []string
	domainLists []string
	rdap        *rdapClient
	// own are the domains of this service, never checked.
	own []string
}

func newReputationChecker(c ReputationConfig, resolver mailauth.Resolver, own []string) *reputationChecker {
	if c.Disabled {
		return nil
	}
	ip, domain := c.zones()
	r := &reputationChecker{resolver: resolver, ipLists: ip, domainLists: domain, own: own}
	if !c.RDAPDisabled {
		r.rdap = newRDAPClient()
	}
	return r
}

// maxDomainChecks bounds the domains checked per mail.
const (
	maxDomainChecks = 15
	maxRDAPChecks   = 8
)

// check queries every list for the IPs and domains, in parallel.
func (r *reputationChecker) check(ctx context.Context, ips, domains []subject) reputation {
	var rep reputation
	if r == nil {
		return rep
	}
	domains = slices.DeleteFunc(slices.Clone(domains), func(s subject) bool {
		return s.Value == "" || slices.Contains(r.own, s.Value)
	})
	if len(domains) > maxDomainChecks {
		domains = domains[:maxDomainChecks]
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	query := func(s subject, zone, name string, decode func(string, netip.Addr) (string, string, bool)) {
		defer wg.Done()
		addrs, err := r.resolver.LookupNetIP(ctx, "ip4", name)
		mu.Lock()
		defer mu.Unlock()
		rep.Checked++
		if err != nil || len(addrs) == 0 {
			return // not listed, or no answer
		}
		meaning, level, ok := decode(zone, addrs[0])
		if !ok {
			if !slices.Contains(rep.Errors, zone) {
				rep.Errors = append(rep.Errors, zone)
			}
			return
		}
		rep.Listings = append(rep.Listings, listing{Subject: s.Value, Role: s.Role, List: zoneName(zone), Code: addrs[0].String(), Meaning: meaning, Level: level})
	}
	for _, s := range ips {
		ip, err := netip.ParseAddr(s.Value)
		if err != nil {
			continue
		}
		for _, zone := range r.ipLists {
			wg.Add(1)
			go query(s, zone, reverseIP(ip)+"."+zone, ipListing)
		}
	}
	for _, s := range domains {
		for _, zone := range r.domainLists {
			wg.Add(1)
			go query(s, zone, s.Value+"."+zone, domainListing)
		}
	}
	if r.rdap != nil {
		seen := map[string]bool{}
		for _, s := range domains {
			if seen[s.Value] || len(seen) == maxRDAPChecks {
				continue
			}
			seen[s.Value] = true
			rep.Domains = append(rep.Domains, domainAge{Domain: s.Value, Role: s.Role})
		}
		for i := range rep.Domains {
			wg.Add(1)
			go func(d *domainAge) {
				defer wg.Done()
				registered, err := r.rdap.registration(ctx, d.Domain)
				mu.Lock()
				defer mu.Unlock()
				d.Registered = registered
				if err != nil {
					d.Error = err.Error()
				}
			}(&rep.Domains[i])
		}
	}
	wg.Wait()
	slices.SortStableFunc(rep.Listings, func(a, b listing) int { return spamSeverity[b.Level] - spamSeverity[a.Level] })
	return rep
}

// reverseIP writes an address the way blocklists are queried:
// 192.0.2.1 → 1.2.0.192, IPv6 as reversed nibbles.
func reverseIP(ip netip.Addr) string {
	if ip.Is4() || ip.Is4In6() {
		b := ip.Unmap().As4()
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	nibbles := make([]string, 0, 32)
	for i := len(b) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", b[i]&0xf), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(nibbles, ".")
}

// zoneName removes the DQS key from a zone shown on the page.
func zoneName(zone string) string {
	if _, rest, ok := strings.Cut(zone, "."); ok && strings.HasSuffix(zone, ".dq.spamhaus.net") {
		return rest
	}
	return zone
}

func isSpamhaus(zone string) bool {
	return strings.HasSuffix(zone, ".spamhaus.org") || strings.HasSuffix(zone, ".spamhaus.net")
}

// ipListing decodes the answer of an IP blocklist; ok is false for the
// answers meaning the query was refused.
func ipListing(zone string, code netip.Addr) (meaning, level string, ok bool) {
	b := code.As4()
	if b[0] != 127 {
		return "", "", false
	}
	if isSpamhaus(zone) {
		if b[1] == 255 && b[2] == 255 {
			return "", "", false // 127.255.255.252-255: refused
		}
		switch b[3] {
		case 2, 3:
			return "source de spam connue (Spamhaus SBL)", levelDanger, true
		case 4, 5, 6, 7:
			return "machine piratée ou infectée qui envoie du spam (Spamhaus XBL)", levelDanger, true
		case 9:
			return "réseau détourné par des criminels (Spamhaus DROP)", levelDanger, true
		case 10, 11:
			return "adresse d'accès Internet résidentiel, qui ne devrait pas envoyer de mail directement (Spamhaus PBL)", levelWarning, true
		}
		return "listée par Spamhaus", levelWarning, true
	}
	return "listée comme source de spam", levelDanger, true
}

// domainListing decodes the answer of a domain blocklist.
func domainListing(zone string, code netip.Addr) (meaning, level string, ok bool) {
	b := code.As4()
	if b[0] != 127 {
		return "", "", false
	}
	switch {
	case isSpamhaus(zone):
		if b[1] == 255 || b[3] == 255 {
			return "", "", false
		}
		switch b[3] {
		case 2:
			return "domaine de spam (Spamhaus DBL)", levelDanger, true
		case 4:
			return "domaine de phishing (Spamhaus DBL)", levelDanger, true
		case 5:
			return "domaine diffusant des logiciels malveillants (Spamhaus DBL)", levelDanger, true
		case 6:
			return "domaine de contrôle de logiciels malveillants (Spamhaus DBL)", levelDanger, true
		}
		if b[3] >= 102 && b[3] <= 106 {
			return "domaine légitime détourné pour du spam ou du phishing (Spamhaus DBL)", levelWarning, true
		}
		return "listé par Spamhaus", levelWarning, true
	case strings.HasSuffix(zone, "surbl.org"):
		if b[3] == 1 {
			return "", "", false // access blocked
		}
		var kinds []string
		level := levelWarning
		for bit, kind := range map[byte]string{8: "phishing", 16: "logiciels malveillants", 64: "abus et spam", 128: "site piraté"} {
			if b[3]&bit != 0 {
				kinds = append(kinds, kind)
				if bit == 8 || bit == 16 {
					level = levelDanger
				}
			}
		}
		slices.Sort(kinds)
		return "listé par SURBL : " + strings.Join(kinds, ", "), level, true
	}
	return "listé comme domaine de spam", levelDanger, true
}

// rdapClient finds the registration date of domains, from the RDAP server
// of their registry (IANA bootstrap, RFC 9224).
type rdapClient struct {
	client    *http.Client
	bootstrap string

	mu        sync.Mutex
	servers   map[string]string // TLD → base URL
	loaded    time.Time
	dates     map[string]rdapEntry
	userAgent string
}

type rdapEntry struct {
	registered time.Time
	err        error
	expires    time.Time
}

const rdapCacheDuration = 24 * time.Hour

func newRDAPClient() *rdapClient {
	return &rdapClient{
		client: &http.Client{
			Timeout: 6 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 || req.URL.Scheme != "https" {
					return errors.New("redirection refusée")
				}
				return nil
			},
		},
		bootstrap: "https://data.iana.org/rdap/dns.json",
		dates:     map[string]rdapEntry{},
		userAgent: "mailtoolkit_webserver (mail analysis)",
	}
}

var errNoRDAP = errors.New("pas de serveur RDAP pour cette extension")

// registration returns the registration date of a domain.
func (c *rdapClient) registration(ctx context.Context, domain string) (time.Time, error) {
	c.mu.Lock()
	if e, ok := c.dates[domain]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e.registered, e.err
	}
	c.mu.Unlock()

	server, err := c.server(ctx, domain)
	var registered time.Time
	if err == nil {
		registered, err = c.query(ctx, server, domain)
	}
	c.mu.Lock()
	if len(c.dates) > 10000 {
		clear(c.dates)
	}
	c.dates[domain] = rdapEntry{registered, err, time.Now().Add(rdapCacheDuration)}
	c.mu.Unlock()
	return registered, err
}

// server returns the RDAP base URL for the TLD of a domain.
func (c *rdapClient) server(ctx context.Context, domain string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.servers == nil || time.Since(c.loaded) > rdapCacheDuration {
		var bootstrap struct {
			Services [][][]string `json:"services"`
		}
		if err := c.getJSON(ctx, c.bootstrap, &bootstrap); err != nil {
			if c.servers == nil {
				return "", fmt.Errorf("annuaire RDAP de l'IANA : %w", err)
			}
		} else {
			c.servers = map[string]string{}
			for _, service := range bootstrap.Services {
				if len(service) != 2 || len(service[1]) == 0 {
					continue
				}
				base := service[1][0]
				for _, u := range service[1] {
					if strings.HasPrefix(u, "https://") {
						base = u
						break
					}
				}
				for _, tld := range service[0] {
					c.servers[strings.ToLower(tld)] = strings.TrimSuffix(base, "/") + "/"
				}
			}
			c.loaded = time.Now()
		}
	}
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	base, ok := c.servers[tld]
	if !ok || !strings.HasPrefix(base, "https://") {
		return "", errNoRDAP
	}
	return base, nil
}

// query asks the registry for the registration event of a domain.
func (c *rdapClient) query(ctx context.Context, base, domain string) (time.Time, error) {
	var answer struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := c.getJSON(ctx, base+"domain/"+domain, &answer); err != nil {
		return time.Time{}, err
	}
	for _, e := range answer.Events {
		if e.Action == "registration" {
			t, err := time.Parse(time.RFC3339, e.Date)
			if err != nil {
				return time.Time{}, fmt.Errorf("date illisible %q", e.Date)
			}
			return t, nil
		}
	}
	return time.Time{}, errors.New("date de création non publiée par le registre")
}

func (c *rdapClient) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errors.New("domaine inconnu du registre")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("réponse %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(v)
}
