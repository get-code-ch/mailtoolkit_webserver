package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"github.com/get-code-ch/mailtoolkit_webserver/smime"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/get-code-ch/mailtoolkit_webserver/internal/testcfb"
)

// testMsg builds a minimal Outlook message.
func testMsg(subject string) []byte {
	var data []byte
	for _, u := range utf16.Encode([]rune(subject + "\x00")) {
		data = binary.LittleEndian.AppendUint16(data, u)
	}
	return testcfb.Build(
		testcfb.Stream("__properties_version1.0", make([]byte, 32)),
		testcfb.Stream("__substg1.0_0037001F", data),
		testcfb.Stream("__substg1.0_1000001E", []byte("body")),
	)
}

func newTestServer(t *testing.T) *server {
	t.Helper()
	store := newTestStore(t, t.TempDir(), &testClock{time.Now()})
	templates, err := template.New("").Funcs(templateFuncs).ParseFS(views, "view/*.html")
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		store:         store,
		templates:     templates,
		limiter:       newRateLimiter(100, time.Hour),
		resolver:      mapResolver{},
		auth:          newBoundedCache[headerAnalysis](8),
		maxUploadSize: 1 << 20,
	}
}

func postFile(t *testing.T, handler http.Handler, target, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, _ := form.CreateFormFile("file", filename)
	part.Write(data)
	form.Close()
	request := httptest.NewRequest(http.MethodPost, target, &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func get(handler http.Handler, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func TestUpload(t *testing.T) {
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	analysis := regexp.MustCompile(`^/inbox/([a-z2-7]{26})/[0-9a-f]{24}/1$`)

	// An .eml creates a mailbox and shows its analysis.
	response := postFile(t, handler, "/upload", "suspect.eml", readTestdata(t, "multipartcomplex.eml"))
	location := response.Header().Get("Location")
	m := analysis.FindStringSubmatch(location)
	if response.Code != http.StatusSeeOther || m == nil {
		t.Fatalf("upload: %d %q", response.Code, location)
	}
	token := m[1]
	if page := get(handler, location); page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Hello Bonjour Coucou !!") {
		t.Fatalf("analysis page: %d", page.Code)
	}

	// An .msg added to the same mailbox, whatever its name.
	response = postFile(t, handler, "/inbox/"+token+"/upload", "export", testMsg("Réunion Outlook"))
	location = response.Header().Get("Location")
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(location, "/inbox/"+token+"/") {
		t.Fatalf("msg upload: %d %q", response.Code, location)
	}
	page := get(handler, location).Body.String()
	if !strings.Contains(page, "Réunion Outlook") || !strings.Contains(page, "converti pour l'analyse") || !strings.Contains(page, "ne peuvent donc pas être vérifiées") {
		t.Errorf("msg analysis page misses the subject or the conversion notes")
	}

	inbox := get(handler, "/inbox/"+token).Body.String()
	if strings.Count(inbox, "Fichier envoyé le") != 2 || !strings.Contains(inbox, "Outlook .msg") {
		t.Errorf("inbox does not list both uploads")
	}

	for name, tt := range map[string]struct {
		target string
		data   []byte
		code   int
	}{
		"not a mail":      {"/upload", []byte("%PDF-1.4 just a pdf"), http.StatusUnprocessableEntity},
		"word document":   {"/upload", testcfb.Build(testcfb.Stream("WordDocument", []byte("w"))), http.StatusUnprocessableEntity},
		"too large":       {"/upload", append([]byte("From: a@b.example\r\nSubject: x\r\n\r\n"), make([]byte, 2<<20)...), http.StatusRequestEntityTooLarge},
		"unknown mailbox": {"/inbox/aaaaaaaaaaaaaaaaaaaaaaaaaa/upload", readTestdata(t, "nomime.eml"), http.StatusNotFound},
		"empty":           {"/upload", nil, http.StatusBadRequest},
	} {
		if got := postFile(t, handler, tt.target, "file", tt.data).Code; got != tt.code {
			t.Errorf("%s: %d, want %d", name, got, tt.code)
		}
	}
}

func TestCarrierWithMsgAttachment(t *testing.T) {
	s := newTestServer(t)
	mailbox, err := s.store.Create()
	if err != nil {
		t.Fatal(err)
	}
	carrier := buildCarrier("Content-Type: application/vnd.ms-outlook\r\nContent-Disposition: attachment; filename=\"suspect.msg\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + wrapBase64(testMsg("Message Outlook transféré")))
	env := deliver(t, s.store, mailbox.Address, carrier)

	submission, err := s.store.Submission(mailbox.Token, env.ID)
	if err != nil || len(submission.Analyzed) != 1 || submission.Analyzed[0].Subject != "Message Outlook transféré" {
		t.Fatalf("submission = %+v, %v", submission, err)
	}
	mail, info, err := s.store.Analyzed(mailbox.Token, env.ID, 1)
	if err != nil || info.Format != formatMSG || mail.Header.Subject != "Message Outlook transféré" {
		t.Errorf("analyzed msg: %+v %+v %v", mail.Header, info, err)
	}
}

func TestDeleteSubmission(t *testing.T) {
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	location := postFile(t, handler, "/upload", "suspect.eml", []byte("From: a@example.org\r\nSubject: to delete\r\n\r\nbody\r\n")).Header().Get("Location")
	parts := strings.Split(location, "/") // "", inbox, token, id, n
	if len(parts) != 5 {
		t.Fatalf("location %q", location)
	}
	inbox, del := "/inbox/"+parts[2], "/inbox/"+parts[2]+"/"+parts[3]+"/delete"
	if page := get(handler, location).Body.String(); !strings.Contains(page, `action="`+del+`"`) {
		t.Error("analysis page has no delete button")
	}
	if page := get(handler, inbox).Body.String(); !strings.Contains(page, "to delete") || !strings.Contains(page, `action="`+del+`"`) {
		t.Error("inbox does not list the mail with a delete button")
	}

	post := func(target string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, target, nil))
		return recorder
	}
	if r := post(del); r.Code != http.StatusSeeOther || r.Header().Get("Location") != inbox {
		t.Fatalf("delete: %d %q", r.Code, r.Header().Get("Location"))
	}
	if get(handler, location).Code != http.StatusNotFound {
		t.Error("deleted mail still served")
	}
	if page := get(handler, inbox).Body.String(); strings.Contains(page, "to delete") {
		t.Error("deleted mail still listed")
	}
	if r := post(del); r.Code != http.StatusNotFound {
		t.Errorf("second delete: %d", r.Code)
	}
	if r := post("/inbox/" + parts[2] + "/../delete"); r.Code == http.StatusSeeOther {
		t.Error("invalid id accepted")
	}
	if code := get(handler, del).Code; code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Errorf("GET on the delete URL: %d", code)
	}
}

func TestModifiedFieldHighlighted(t *testing.T) {
	key, err := os.ReadFile("mailauth/testdata/dkim-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("mailauth/testdata/dkim-relaxed-relaxed.eml")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)
	s.resolver = mapResolver{txt: map[string][]string{"test._domainkey.example.com": {strings.TrimSpace(string(key))}}}
	handler := s.routes(t.TempDir())
	location := postFile(t, handler, "/upload", "x.eml", bytes.Replace(raw, []byte("Subject:   Is dinner"), []byte("Subject: [EXT] Is dinner"), 1)).Header().Get("Location")
	page := get(handler, location).Body.String()
	if !strings.Contains(page, `<tr class="modified">`) || !strings.Contains(page, "un préfixe a été ajouté au sujet") || !strings.Contains(page, "Is dinner ready? folded continuation") {
		t.Error("modified subject not highlighted")
	}
}

func TestSMIMEPage(t *testing.T) {
	root, err := os.ReadFile("smime/testdata/root.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	s := newTestServer(t)
	s.smime = &smime.Verifier{Roots: roots}
	s.smimeCache = newBoundedCache[smime.Result](4)
	handler := s.routes(t.TempDir())

	for name, want := range map[string][]string{
		"detached.eml":  {"Signature S/MIME", "Example Org", "NTRCH-CHE-123.456.789", "organisation vérifiée", "Signé électroniquement par Example Org", "Test SMIME ICA"},
		"encrypted.eml": {"Signature S/MIME", "chiffré"},
	} {
		raw, err := os.ReadFile("smime/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		location := postFile(t, handler, "/upload", name, raw).Header().Get("Location")
		page := get(handler, location)
		if page.Code != http.StatusOK {
			t.Fatalf("%s: %d", name, page.Code)
		}
		for _, w := range want {
			if !strings.Contains(page.Body.String(), w) {
				t.Errorf("%s: %q missing", name, w)
			}
		}
	}
}
