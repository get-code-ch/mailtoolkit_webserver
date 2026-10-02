package main

import (
	"bytes"
	"encoding/binary"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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
	templates, err := template.New("").Funcs(template.FuncMap{"resultClass": resultClass}).ParseFS(views, "view/*.html")
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
