package main

import (
	"bytes"
	"errors"
	"html/template"
	"log"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"

	"github.com/get-code-ch/mailtoolkit"
)

// Mail parts are sent by third parties: they are rendered sandboxed (no
// script, unique origin) and may only load images from this server, so
// remote tracking images are blocked too.
const (
	appCSP  = "default-src 'self'; frame-ancestors 'self'"
	mailCSP = "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors 'self'"
)

// removeCid turns src="cid:xxx" into a link relative to /mail/{id}/, served
// by mailContent.
var removeCid = regexp.MustCompile(`(?mi)(src=["]?)(cid:)(["]?)`)

type mailTpl struct {
	From       string
	To         string
	Subject    string
	Date       string
	Content    []Href
	Attachment []Href
}

type Href struct {
	Link string
	Text string
}

type server struct {
	store     *mailStore
	templates *template.Template
}

func (s *server) routes(staticFolder string) http.Handler {
	mux := http.NewServeMux()
	// Display list of emails
	mux.HandleFunc("GET /{$}", s.root)
	// Display select mail content
	mux.HandleFunc("GET /display/{id}/{content}", s.displayContent)
	mux.HandleFunc("GET /mail/{id}/{content}", s.mailContent)
	mux.HandleFunc("GET /mail/{id}/attachment/{attachment}", s.mailAttachment)
	// Serving static files
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticFolder))))
	return noSniff(mux)
}

func noSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *server) root(w http.ResponseWriter, r *http.Request) {
	ids, err := s.store.ids()
	if err != nil {
		serverError(w, "listing mails", err)
		return
	}

	p := []mailTpl{}
	for _, id := range ids {
		mail, err := s.store.get(id)
		if err != nil {
			log.Printf("mail %s: %v", id, err)
			continue
		}
		escapedID := url.PathEscape(id)
		t := mailTpl{From: mail.Header.From, To: mail.Header.To, Subject: mail.Header.Subject, Date: mail.Header.Date}
		for _, key := range contentKeys(mail.Contents) {
			ct := mail.Contents[key].ContentInfo.Type
			t.Content = append(t.Content, Href{"/display/" + escapedID + "/" + url.PathEscape(key), ct.Type + "/" + ct.Subtype})
		}
		for _, name := range sortedKeys(mail.Attachments) {
			t.Attachment = append(t.Attachment, Href{"/mail/" + escapedID + "/attachment/" + url.PathEscape(name), name})
		}
		p = append(p, t)
	}

	s.render(w, "home.html", struct {
		Title string
		Mail  []mailTpl
	}{Title: "mailtoolkit demo webserver", Mail: p})
}

func (s *server) displayContent(w http.ResponseWriter, r *http.Request) {
	mail, content, ok := s.lookupContent(w, r)
	if !ok {
		return
	}
	s.render(w, "mail.html", struct {
		Title       string
		Header      mailtoolkit.Header
		ContentInfo mailtoolkit.ContentInfo
		Content     string
	}{
		Title:       "mailtoolkit demo webserver (Display Mail)",
		Header:      mail.Header,
		ContentInfo: content.ContentInfo,
		Content:     "/mail/" + url.PathEscape(r.PathValue("id")) + "/" + url.PathEscape(r.PathValue("content")),
	})
}

func (s *server) mailContent(w http.ResponseWriter, r *http.Request) {
	_, content, ok := s.lookupContent(w, r)
	if !ok {
		return
	}
	data, err := content.Decode()
	if err != nil {
		serverError(w, "decoding content", err)
		return
	}
	if content.ContentInfo.Type.Type == "text" {
		data = removeCid.ReplaceAll(data, []byte("$1$3"))
	}

	w.Header().Set("Content-Type", formatContentType(content.ContentInfo.Type))
	w.Header().Set("Content-Security-Policy", mailCSP)
	w.Write(data)
}

func (s *server) mailAttachment(w http.ResponseWriter, r *http.Request) {
	mail, ok := s.lookupMail(w, r)
	if !ok {
		return
	}
	name := r.PathValue("attachment")
	attachment, ok := mail.Attachments[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := attachment.Decode()
	if err != nil {
		serverError(w, "decoding attachment", err)
		return
	}

	w.Header().Set("Content-Type", formatContentType(attachment.ContentInfo.Type))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Security-Policy", mailCSP)
	w.Write(data)
}

func (s *server) lookupMail(w http.ResponseWriter, r *http.Request) (mailtoolkit.Mail, bool) {
	mail, err := s.store.get(r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		http.NotFound(w, r)
		return mail, false
	}
	if err != nil {
		serverError(w, "reading mail", err)
		return mail, false
	}
	return mail, true
}

func (s *server) lookupContent(w http.ResponseWriter, r *http.Request) (mailtoolkit.Mail, mailtoolkit.Content, bool) {
	mail, ok := s.lookupMail(w, r)
	if !ok {
		return mail, mailtoolkit.Content{}, false
	}
	content, ok := mail.Contents[r.PathValue("content")]
	if !ok {
		http.NotFound(w, r)
	}
	return mail, content, ok
}

// render executes the template in a buffer so that a failing template gives a
// clean error page.
func (s *server) render(w http.ResponseWriter, name string, data any) {
	var buffer bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buffer, name, data); err != nil {
		serverError(w, "rendering "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", appCSP)
	buffer.WriteTo(w)
}

func serverError(w http.ResponseWriter, context string, err error) {
	log.Printf("%s: %v", context, err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func formatContentType(ct mailtoolkit.ContentType) string {
	if formatted := mime.FormatMediaType(ct.Type+"/"+ct.Subtype, ct.Parameters); formatted != "" {
		return formatted
	}
	return "application/octet-stream"
}

// contentKeys sorts positional keys ("0", "1"...) numerically, before the
// Content-ID ones.
func contentKeys(contents map[string]mailtoolkit.Content) []string {
	keys := sortedKeys(contents)
	sort.SliceStable(keys, func(i, j int) bool {
		a, errA := strconv.Atoi(keys[i])
		b, errB := strconv.Atoi(keys[j])
		switch {
		case errA == nil && errB == nil:
			return a < b
		default:
			return errA == nil && errB != nil
		}
	})
	return keys
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
