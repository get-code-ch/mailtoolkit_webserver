package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/filecheck"
)

func TestNormalizeEntry(t *testing.T) {
	for _, tt := range []struct{ kind, in, out string }{
		{listDomain, " https://Évil.Example/login ", "xn--vil-9la.example"},
		{listDomain, "phish.example.", "phish.example"},
		{listSender, "Jean <Jean.Dupont@Example.ORG>", "jean.dupont@example.org"},
		{listHash, strings.Repeat("AB", 32), strings.Repeat("ab", 32)},
	} {
		if got, err := normalizeEntry(tt.kind, tt.in); err != nil || got != tt.out {
			t.Errorf("%s %q: %q %v", tt.kind, tt.in, got, err)
		}
	}
	for _, tt := range [][2]string{{listDomain, "localhost"}, {listSender, "nobody"}, {listHash, "abc"}, {"ip", "1.2.3.4"}} {
		if _, err := normalizeEntry(tt[0], tt[1]); err == nil {
			t.Errorf("%v accepted", tt)
		}
	}
}

func TestListsRisk(t *testing.T) {
	dir := t.TempDir()
	store, err := newListStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range [][4]string{
		{listDomain, "phish.example", verdictBlock, "campagne de juin"},
		{listSender, "ceo@partner.example", verdictTrust, ""},
		{listHash, strings.Repeat("a", 64), verdictBlock, ""},
		{listHash, strings.Repeat("b", 64), verdictTrust, "formulaire interne"},
		{listDomain, "partner.example", verdictTrust, ""},
	} {
		if err := store.add(e[0], e[1], e[2], e[3]); err != nil {
			t.Fatal(err)
		}
	}
	// Reloaded from the file, newest first; a second add replaces.
	store.add(listDomain, "phish.example", verdictBlock, "campagne de juillet")
	store, _ = newListStore(dir)
	entries := store.all()
	if len(entries) != 5 || entries[0].Note != "campagne de juillet" {
		t.Fatalf("%+v", entries)
	}
	lists := store.snapshot()
	if got := lists.trustedDomains(); len(got) != 1 || got[0] != "partner.example" {
		t.Errorf("%v", got)
	}

	link := analyzeLink("https://login.phish.example/x", "", "lien", "text/html")
	r := assessRisk(riskInput{Auth: authenticated("shop.example", ""), Links: []Link{link}, Lists: lists})
	if r.Light != riskRed || !strings.Contains(r.Reasons[0].Simple, "liste noire") {
		t.Errorf("blocked link: %+v", r.Reasons)
	}
	r = assessRisk(riskInput{Auth: authenticated("shop.example", ""), Lists: lists,
		Destinations: []Link{{URL: "https://phish.example/final", Source: "destination"}}})
	if r.Light != riskRed {
		t.Errorf("blocked destination: %+v", r.Reasons)
	}

	trusted := authenticated("partner.example", "")
	trusted.FromAddress = "ceo@partner.example"
	r = assessRisk(riskInput{Auth: trusted, Lists: lists, Links: []Link{analyzeLink("https://evil.example/", "www.bank.example", "lien", "text/html")}})
	if !r.Trusted || r.Light != riskGreen {
		t.Errorf("trusted sender: %s %+v", r.Light, r.Reasons)
	}

	attachments := []attachmentView{
		{Report: filecheck.Report{Name: "virus.pdf", SHA256: strings.Repeat("a", 64)}},
		{Report: filecheck.Report{Name: "form.html", SHA256: strings.Repeat("b", 64),
			Alerts: []filecheck.Alert{{Level: filecheck.LevelDanger, Message: "Contient du JavaScript"}}}},
	}
	r = assessRisk(riskInput{Auth: authenticated("shop.example", ""), Lists: lists, Attachments: attachments})
	if r.Score != 4 || !strings.Contains(r.Reasons[0].Simple, "virus.pdf") || !strings.Contains(strings.Join(r.Positives, " "), "form.html") {
		t.Errorf("files: %d %+v %v", r.Score, r.Reasons, r.Positives)
	}
}

func TestAdminLists(t *testing.T) {
	s := newTestServer(t)
	s.adminToken = strings.Repeat("k", 32)
	s.stats, _ = newStatsStore(t.TempDir(), time.Now)
	s.lists, _ = newListStore(t.TempDir())
	handler := s.routes(t.TempDir())
	post := func(form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/admin/lists", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("admin", s.adminToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	form := url.Values{"action": {"add"}, "kind": {"domain"}, "value": {"phish.example"}, "verdict": {"block"}, "days": {"7"}}
	if w := post(form); w.Code != http.StatusForbidden {
		t.Errorf("without CSRF token: %d", w.Code)
	}
	form.Set("csrf", s.csrfToken())
	if w := post(form); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin?days=7#lists" {
		t.Errorf("%d %s", w.Code, w.Header().Get("Location"))
	}
	form.Set("value", "not a domain")
	if w := post(form); !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Errorf("invalid value accepted: %s", w.Header().Get("Location"))
	}
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.SetBasicAuth("admin", s.adminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "<code>phish.example</code>") || !strings.Contains(w.Body.String(), s.csrfToken()) {
		t.Error("entry or token missing on the page")
	}

	// The blocked domain turns a mail linking to it red.
	raw, _ := os.ReadFile("testdata/multipart.eml")
	mail := strings.Replace(string(raw), "</body>", `<a href="https://www.phish.example/">ici</a></body>`, 1)
	location := postFile(t, handler, "/upload", "m.eml", []byte(mail)).Header().Get("Location")
	if page := get(handler, location).Body.String(); !strings.Contains(page, "light-red") || !strings.Contains(page, "liste noire de votre organisation") {
		t.Error("blocked domain not applied")
	}

	form.Set("action", "delete")
	form.Set("value", "phish.example")
	post(form)
	if len(s.lists.all()) != 0 {
		t.Error("entry not removed")
	}
}
