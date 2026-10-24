package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
)

// TestMain, with I18N_DUMP=file, renders every page of the tests in
// English and writes the texts left untranslated to the file (the tests
// checking French texts then fail). I18N_CORPUS=folder adds the mails of a
// folder to the pages rendered.
func TestMain(m *testing.M) {
	dump := os.Getenv("I18N_DUMP")
	if dump == "" {
		os.Exit(m.Run())
	}
	var mu sync.Mutex
	found := map[string]bool{}
	forcedLanguage = langEN
	onUntranslated = func(s string) {
		if looksFrench(s) {
			mu.Lock()
			found[s] = true
			mu.Unlock()
		}
	}
	code := m.Run()
	var list []string
	for s := range found {
		list = append(list, s)
	}
	slices.Sort(list)
	os.WriteFile(dump, []byte(strings.Join(list, "\n")+"\n"), 0o600)
	os.Exit(code)
}

// looksFrench reports a French text, not a value (domain, address,
// number, result).
func looksFrench(s string) bool {
	if strings.ContainsAny(s, "éèàçêûôîÉÀ«»") {
		return true
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '\'' }) {
		switch w {
		case "le", "la", "les", "des", "du", "un", "une", "est", "pas", "de", "et", "pour", "par", "sur", "avec", "sans", "dans",
			"au", "aux", "ce", "cette", "qui", "que", "ne", "aucun", "aucune", "vers":
			return true
		}
	}
	return false
}

func TestI18NCorpus(t *testing.T) {
	folder := os.Getenv("I18N_CORPUS")
	if folder == "" {
		t.Skip("I18N_CORPUS not set")
	}
	files, _ := filepath.Glob(filepath.Join(folder, "*.eml"))
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		location := postFile(t, handler, "/upload", filepath.Base(f), raw).Header().Get("Location")
		if location == "" {
			continue
		}
		get(handler, location)
		get(handler, strings.Join(strings.Split(location, "/")[:3], "/"))
	}
}

func TestLanguage(t *testing.T) {
	for _, tt := range []struct{ query, cookie, accept, want string }{
		{"", "", "", langFR},
		{"", "", "fr-CH,fr;q=0.9,en;q=0.8", langFR},
		{"", "", "en-US,en;q=0.9,fr;q=0.8", langEN},
		{"", "", "de-CH,de;q=0.9", langEN},
		{"", "fr", "en-US", langFR},
		{"en", "fr", "fr", langEN},
		{"xx", "", "", langFR},
	} {
		r := httptest.NewRequest(http.MethodGet, "/?lang="+tt.query, nil)
		if tt.cookie != "" {
			r.AddCookie(&http.Cookie{Name: langCookie, Value: tt.cookie})
		}
		r.Header.Set("Accept-Language", tt.accept)
		if got := language(r); got != tt.want {
			t.Errorf("%+v: %s", tt, got)
		}
	}
}

func TestLanguageSwitch(t *testing.T) {
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	w := get(handler, "/inbox/x/y/1?part=0&lang=en&hop=2")
	cookie := w.Header().Get("Set-Cookie")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/inbox/x/y/1?hop=2&part=0" || !strings.HasPrefix(cookie, "lang=en;") {
		t.Errorf("%d %s %s", w.Code, w.Header().Get("Location"), cookie)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: langCookie, Value: langEN})
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	page := w.Body.String()
	if !strings.Contains(page, `<html lang="en">`) || !strings.Contains(page, "Inspect a mail") || strings.Contains(page, "Inspectez") ||
		w.Header().Get("Content-Language") != "en" {
		t.Error("home page not in English")
	}
	if page := get(handler, "/").Body.String(); !strings.Contains(page, "Inspectez un mail") {
		t.Error("home page not in French by default")
	}
}

func TestTranslateHTML(t *testing.T) {
	tr := newTranslator(map[string]string{"Copier": "Copy", "Supprimer": "Delete", "Valeur": "Value", "rien": "nothing"},
		[]pattern{{"Un lien est piégé : %s", "A link is booby-trapped: %s"}, {"Analyse : %s", "Analysis: %s"},
			{"%d serveurs", "%s servers"}, {"%d % des analyses", "%s%% of the analyses"}, {"Le site %s est récent", "The site %s is recent"}}, nil)
	in := `<html lang="fr"><title>Analyse : mail.eml</title><p>  Copier
	</p><button title="Supprimer">Supprimer</button><code>Supprimer</code><code>example.com</code><pre>Copier</pre>` +
		`<span translate="no">Copier <b>Valeur</b></span><i>Valeur</i><p>3 serveurs, 40 % des analyses</p><p>4 serveurs</p>` +
		`<p>12 % des analyses</p><p>Un lien est piégé : le site evil.example est récent</p><dd><strong>pass</strong> : rien</dd>`
	got := string(tr.translateHTML([]byte(in), langEN))
	if en, _ := english.translate("Pas d'identifiant Message-ID : inhabituel pour un vrai serveur de messagerie · Date absente ou invalide"); en !=
		"No Message-ID: unusual for a real mail server · Date missing or invalid" {
		t.Errorf("joined details: %q", en)
	}
	if en, _ := english.translate("rouge · au plus 3 analyses par jour"); en != "red · at most 3 analyses per day" {
		t.Errorf("legend: %q", en)
	}
	want := `<html lang="en"><title>Analysis: mail.eml</title><p>  Copy
	</p><button title="Delete">Delete</button><code>Delete</code><code>example.com</code><pre>Copier</pre>` +
		`<span translate="no">Copier <b>Valeur</b></span><i>Value</i><p>3 serveurs, 40 % des analyses</p><p>4 servers</p>` +
		`<p>12% of the analyses</p><p>A link is booby-trapped: the site evil.example is recent</p><dd><strong>pass</strong>: nothing</dd>`
	if got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

// TestEnglishCoverage renders the pages of the site in English and checks
// that no French text of the interface is left.
func TestEnglishCoverage(t *testing.T) {
	if os.Getenv("I18N_DUMP") != "" {
		t.Skip("dump mode")
	}
	var mu sync.Mutex
	var left []string
	onUntranslated = func(s string) {
		mu.Lock()
		defer mu.Unlock()
		if looksFrench(s) && !slices.Contains(left, s) {
			left = append(left, s)
		}
	}
	defer func() { onUntranslated = nil }()

	s := newTestServer(t)
	s.adminToken = strings.Repeat("k", 32)
	s.stats, _ = newStatsStore(t.TempDir(), time.Now)
	s.lists, _ = newListStore(t.TempDir())
	s.lists.add(listDomain, "phish.example", verdictBlock, "")
	s.store.onSubmission = s.stats.recordSubmission
	handler := s.routes(t.TempDir())
	english := func(target string) {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.AddCookie(&http.Cookie{Name: langCookie, Value: langEN})
		r.SetBasicAuth("admin", s.adminToken)
		handler.ServeHTTP(httptest.NewRecorder(), r)
	}
	english("/")
	for _, f := range []string{"testdata/multipart.eml", "testdata/multipartcomplex.eml", "smime/testdata/detached.eml",
		"smime/testdata/encrypted.eml", "mailauth/testdata/arc-chain.eml"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		location := postFile(t, handler, "/upload", filepath.Base(f), raw).Header().Get("Location")
		english(location)
		english(strings.Join(strings.Split(location, "/")[:3], "/"))
	}
	english("/securite")
	english("/admin?days=7")
	// Values of the test mails, not texts of the site.
	data := []string{"Hello Bonjour", "Is dinner ready", "Example ", "Test SMIME", "Joe SixPack", "dkim test", "Test message", "— Test PKI",
		"Claude Sample", "Microsoft Outlook", "Lisez nos articles", "Réunion Outlook", "Affiche sept", "test 2", "to delete", "RSA SHA-256",
		"Microsoft 365 (Exchange Online Protection)", "Dr.Web", "TLSv1", "<meta"}
	for _, s := range left {
		if !slices.ContainsFunc(data, func(d string) bool { return strings.Contains(s, d) }) && !strings.Contains(s, "@") {
			t.Errorf("untranslated: %q", s)
		}
	}
}
