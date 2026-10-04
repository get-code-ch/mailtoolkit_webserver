package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// The links of a mail can be followed by the server, without running any
// code: the redirections (HTTP, meta refresh, literal JavaScript
// assignments) are followed, and the final page is read for a password
// field, a form, a captcha and the brand it claims. The sender sees a
// visit; single-use links (confirmations, unsubscriptions) are never
// followed automatically.

// Bounds of the visits.
const (
	maxRedirects     = 8
	maxPage          = 1 << 20
	visitTimeout     = 7 * time.Second
	maxAutoVisits    = 6
	visitMailTimeout = 15 * time.Second
	// browserUserAgent is the user agent of a common browser: phishing
	// kits show a harmless page to the robots.
	browserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

// pageVisit is the result of the visit of a link.
type pageVisit struct {
	URL string
	// Chain lists the addresses gone through, the link first.
	Chain []visitStep
	// Final is the last address, Status its HTTP status.
	Final  string
	Status int
	Title  string
	// Password is set when the page asks a password, FormHosts are where
	// its forms send.
	Password  bool
	FormHosts []string
	// Captcha names the challenge hiding the page from robots.
	Captcha string
	// Brand is the brand the page claims (title, logo text) while hosted
	// elsewhere.
	Brand string
	// Warnings are the findings of the visit.
	Warnings []LinkWarning
	Error    string
	// Manual is set when the visitor asked for it.
	Manual bool
}

type visitStep struct {
	URL    string
	Status int
	// How the next step was reached: "HTTP", "meta refresh", "JavaScript".
	Via string
}

// Level is the most severe level of the visit.
func (v pageVisit) Level() string {
	return Link{Warnings: v.Warnings}.Level()
}

// FinalHost is the host of the last address.
func (v pageVisit) FinalHost() string {
	if u, err := url.Parse(v.Final); err == nil {
		return displayHost(u.Hostname())
	}
	return ""
}

// linkVisitor follows links through an HTTP client that only connects to
// public addresses.
type linkVisitor struct {
	client *http.Client
	// allowPrivate lets the tests reach their local server.
	allowPrivate bool
}

var errPrivateAddress = errors.New("adresse interne refusée")

func newLinkVisitor() *linkVisitor {
	v := &linkVisitor{}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		// Checked at connection time, after the DNS resolution: a public
		// name resolving to an internal address is refused too.
		Control: func(network, address string, _ syscall.RawConn) error {
			if v.allowPrivate {
				return nil
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !publicAddress(ip) || (port != "80" && port != "443") {
				return errPrivateAddress
			}
			return nil
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		Proxy:                 nil,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	v.client = &http.Client{
		Transport: transport,
		// Redirections are followed one by one, to record them.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       visitTimeout,
	}
	return v
}

// publicAddress reports an address of the internet: not private, loopback,
// link-local, shared (CGNAT), multicast, documentation or reserved.
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var reservedPrefixes = func() []netip.Prefix {
	var list []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7"} {
		list = append(list, netip.MustParsePrefix(s))
	}
	return list
}()

var (
	jsLocation = regexp.MustCompile(`(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)`)
	captchas   = []struct{ marker, name string }{
		{"challenges.cloudflare.com/turnstile", "Cloudflare Turnstile"},
		{"cf-turnstile", "Cloudflare Turnstile"},
		{"hcaptcha.com", "hCaptcha"},
		{"google.com/recaptcha", "reCAPTCHA"},
		{"recaptcha/api.js", "reCAPTCHA"},
	}
)

// visit follows a link and reads the final page.
func (v *linkVisitor) visit(ctx context.Context, raw string) pageVisit {
	result := pageVisit{URL: raw}
	current := raw
	for step := 0; ; step++ {
		u, err := url.Parse(current)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			result.Error = "adresse non visitable"
			return result
		}
		if step > maxRedirects {
			result.Error = "trop de redirections"
			return result
		}
		resp, body, err := v.get(ctx, u)
		if err != nil {
			result.Chain = append(result.Chain, visitStep{URL: current})
			result.Final = current
			result.Error = visitError(err)
			return result
		}
		next, via := "", ""
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "":
			next, via = resp.Header.Get("Location"), "HTTP"
		case strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html"):
			next, via = pageRedirect(body)
		}
		result.Chain = append(result.Chain, visitStep{URL: current, Status: resp.StatusCode, Via: via})
		if next != "" {
			if target, err := u.Parse(next); err == nil && target.String() != current {
				current = target.String()
				continue
			}
		}
		result.Final, result.Status = current, resp.StatusCode
		if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") || resp.Header.Get("Content-Type") == "" {
			readPage(&result, u, body)
		}
		inspectVisit(&result)
		return result
	}
}

func (v *linkVisitor) get(ctx context.Context, u *url.URL) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9,en;q=0.8")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxPage))
	return resp, body, nil
}

func visitError(err error) string {
	switch {
	case errors.Is(err, errPrivateAddress):
		return "le lien mène à une adresse interne : visite refusée"
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(err.Error(), "timeout"):
		return "pas de réponse dans le délai"
	case strings.Contains(err.Error(), "no such host"):
		return "le site n'existe plus (nom de domaine introuvable)"
	case strings.Contains(err.Error(), "certificate"):
		return "certificat HTTPS invalide"
	}
	return "visite impossible : " + err.Error()
}

// pageRedirect finds the redirection of a page: meta refresh, or a literal
// address assigned to location in a script.
func pageRedirect(body []byte) (string, string) {
	z := html.NewTokenizer(bytes.NewReader(body))
	inScript := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return "", ""
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			switch token.DataAtom {
			case atom.Meta:
				attrs := attributes(token)
				if strings.EqualFold(attrs["http-equiv"], "refresh") {
					if i := strings.Index(strings.ToLower(attrs["content"]), "url="); i >= 0 {
						return strings.Trim(attrs["content"][i+4:], `'" `), "meta refresh"
					}
				}
			case atom.Script:
				inScript = token.Type == html.StartTagToken
			}
		case html.EndTagToken:
			inScript = false
		case html.TextToken:
			if inScript {
				if m := jsLocation.FindStringSubmatch(string(z.Text())); m != nil {
					return m[1] + m[2], "JavaScript"
				}
			}
		}
	}
}

// readPage reads the title, the forms, the password fields and the
// captcha of the final page.
func readPage(v *pageVisit, base *url.URL, body []byte) {
	lower := strings.ToLower(string(body))
	for _, c := range captchas {
		if strings.Contains(lower, c.marker) {
			v.Captcha = c.name
			break
		}
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	inTitle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			v.Title = collapseSpaces(v.Title)
			return
		case html.TextToken:
			if inTitle {
				v.Title += string(z.Text())
			}
		case html.EndTagToken:
			inTitle = false
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			attrs := attributes(token)
			switch token.DataAtom {
			case atom.Title:
				inTitle = token.Type == html.StartTagToken && v.Title == ""
			case atom.Input:
				if strings.EqualFold(attrs["type"], "password") {
					v.Password = true
				}
			case atom.Form:
				action := base
				if a, err := base.Parse(attrs["action"]); err == nil {
					action = a
				}
				if h := strings.ToLower(action.Hostname()); h != "" && !slices.Contains(v.FormHosts, h) {
					v.FormHosts = append(v.FormHosts, h)
				}
			}
		}
	}
}

// inspectVisit rates what the visit found.
func inspectVisit(v *pageVisit) {
	warn := func(level, message string) { v.Warnings = append(v.Warnings, LinkWarning{level, message}) }
	final := v.FinalHost()
	host := strings.ToLower(final)
	if u, err := url.Parse(v.Final); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	org := mailauth.OrgDomain(host)
	first := ""
	if u, err := url.Parse(v.URL); err == nil {
		first = strings.ToLower(u.Hostname())
	}
	if len(v.Chain) > 1 && !sameSite(first, host) {
		warn(levelInfo, fmt.Sprintf("Redirige vers %s en %d étape%s", final, len(v.Chain)-1, plural(len(v.Chain)-1)))
	}
	if v.Status >= 400 {
		warn(levelInfo, fmt.Sprintf("La page finale répond %d : elle a peut-être déjà été supprimée, ou elle se cache des robots", v.Status))
	}
	// A new host is analyzed like a link of the mail.
	if !sameSite(first, host) {
		for _, w := range analyzeLink(v.Final, "", "redirection", "").Warnings {
			if w.Level != levelInfo {
				warn(w.Level, "Page finale : "+lowerFirst(w.Message))
			}
		}
	}
	if b := displayBrand(v.Title); b != nil && !official(org, *b) && !officialHost(host, []brand{*b}) {
		v.Brand = b.Name
	}
	onOfficial := officialHost(host, brands) || official(org, brands...)
	switch {
	case v.Password && v.Brand != "":
		warn(levelDanger, fmt.Sprintf("La page se présente comme %s (« %s ») et demande un mot de passe, mais elle est hébergée sur %s : "+
			"c'est une fausse page de connexion", v.Brand, v.Title, final))
	case v.Password && !onOfficial:
		warn(levelDanger, "La page demande un mot de passe sur "+final+" : ne saisissez jamais vos identifiants sur une page ouverte depuis un mail")
	case v.Password:
		warn(levelInfo, "La page demande de se connecter sur "+final+", le site officiel : le lien passe sans doute par une page de partage "+
			"ou un service authentique, qui ne montre pas ce qu'il cache derrière la connexion")
	case v.Brand != "":
		warn(levelWarning, fmt.Sprintf("La page se présente comme %s (« %s ») mais elle est hébergée sur %s", v.Brand, v.Title, final))
	}
	if v.Captcha != "" && !onOfficial {
		warn(levelWarning, "La page est protégée par un captcha ("+v.Captcha+") : les kits d'hameçonnage s'en servent pour se cacher "+
			"des robots d'analyse")
	}
	for _, h := range v.FormHosts {
		if !sameSite(h, host) && mailauth.OrgDomain(h) != org {
			warn(levelWarning, "Le formulaire de la page envoie les données saisies à un autre site : "+h)
		}
	}
}

// singleUse matches the links that perform an action when opened.
var singleUse = regexp.MustCompile(`(?i)unsubscribe|d[ée]sinscri|desabonn|abmeld|optout|opt-out|confirm|verify|verif|activate|activation|reset|token=|magic|one-?time|otp`)

// autoVisits chooses the links followed without asking: the suspicious
// ones, those hiding their destination (shorteners, QR codes, documents,
// sharing services), never the single-use ones nor the trusted domains.
func autoVisits(links []Link, trusted []string) []string {
	var urls []string
	for _, l := range links {
		if len(urls) == maxAutoVisits {
			break
		}
		u, err := url.Parse(l.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || slices.Contains(urls, l.URL) {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if trustedDomain(host, trusted) != "" || (singleUse.MatchString(l.URL) && l.Source != "QR code") {
			continue
		}
		level := l.Level()
		hidden := shorteners[strings.TrimPrefix(host, "www.")] || platformOf(sharingPlatforms, host) != "" ||
			(trackerOf(host) != "" && l.Target == "")
		if level == levelDanger || level == levelWarning || l.Source == "QR code" || l.Source == "pièce jointe" || hidden {
			urls = append(urls, l.URL)
		}
	}
	return urls
}

// visitAll visits links in parallel, within the time of a mail.
func (v *linkVisitor) visitAll(ctx context.Context, urls []string) []pageVisit {
	ctx, cancel := context.WithTimeout(ctx, visitMailTimeout)
	defer cancel()
	visits := make([]pageVisit, len(urls))
	done := make(chan struct{})
	for i, u := range urls {
		go func() {
			visits[i] = v.visit(ctx, u)
			done <- struct{}{}
		}()
	}
	for range urls {
		<-done
	}
	return visits
}

// assessVisits reports what the visits found.
func assessVisits(visits []pageVisit, add func(level string, weight int, anchor, simple, detail string)) {
	for _, v := range visits {
		for _, w := range v.Warnings {
			detail := v.URL
			if v.Final != v.URL {
				detail += " → " + v.Final
			}
			switch w.Level {
			case levelDanger:
				add(levelDanger, 4, "links", "En suivant un lien : "+lowerFirst(w.Message)+".", detail)
			case levelWarning:
				add(levelWarning, 1, "links", "En suivant un lien : "+lowerFirst(w.Message)+".", detail)
			}
		}
	}
}
