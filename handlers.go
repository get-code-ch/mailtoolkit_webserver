package main

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/filecheck"
	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// Mail parts are sent by third parties: they are rendered sandboxed (no
// script, unique origin) and may only load images from this server, so
// remote tracking images are blocked too.
const (
	appCSP  = "default-src 'self'; frame-ancestors 'self'; form-action 'self'"
	mailCSP = "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors 'self'"
)

// removeCid turns src="cid:xxx" into a link relative to the part URL,
// served by mailPart.
var removeCid = regexp.MustCompile(`(?mi)(src=["]?)(cid:)(["]?)`)

type Href struct {
	Link   string
	Text   string
	Active bool
}

type server struct {
	store     *mailboxStore
	templates *template.Template
	limiter   *rateLimiter
	resolver  mailauth.Resolver
	// maxUploadSize bounds the uploaded files and the ingested mails.
	maxUploadSize int64
	hostname      string
	// ingestToken enables POST /ingest, behindCloudflare trusts the visitor
	// address given by Cloudflare.
	ingestToken      string
	behindCloudflare bool
	// auth keeps the header analyses: they need DNS queries and the inbox
	// page reloads itself.
	auth *boundedCache[headerAnalysis]
}

// dnsTimeout bounds the DNS queries of a header analysis.
const dnsTimeout = 15 * time.Second

func (s *server) routes(staticFolder string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /new", s.newMailbox)
	mux.HandleFunc("POST /upload", s.upload)
	mux.HandleFunc("POST /ingest", s.ingest)
	mux.HandleFunc("POST /inbox/{token}/upload", s.upload)
	mux.HandleFunc("GET /inbox/{token}", s.inbox)
	mux.HandleFunc("GET /inbox/{token}/{id}/{n}", s.analysis)
	mux.HandleFunc("GET /inbox/{token}/{id}/{n}/part/{content}", s.mailPart)
	mux.HandleFunc("GET /inbox/{token}/{id}/{n}/attachment/{attachment}", s.mailAttachment)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticFolder))))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Inbox URLs are secret: never leak them to other sites.
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// redirectToHTTPS serves the ACME challenges and redirects everything else
// to the HTTPS port.
func redirectToHTTPS(httpsPort, acmeWebroot string) http.Handler {
	mux := http.NewServeMux()
	if acmeWebroot != "" {
		mux.Handle("GET /.well-known/acme-challenge/", http.FileServer(http.Dir(acmeWebroot)))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if httpsPort != "443" {
			host = net.JoinHostPort(host, httpsPort)
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	return mux
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	s.render(w, "index.html", struct{ Title string }{"Analyse de mail"})
}

func (s *server) newMailbox(w http.ResponseWriter, r *http.Request) {
	if mailbox, ok := s.createMailbox(w, r); ok {
		http.Redirect(w, r, "/inbox/"+mailbox.Token, http.StatusSeeOther)
	}
}

// createMailbox creates a mailbox, rate limited per IP, or writes the error
// response.
func (s *server) createMailbox(w http.ResponseWriter, r *http.Request) (Mailbox, bool) {
	if !s.limiter.allow(s.clientIP(r)) {
		http.Error(w, "Trop de demandes, réessayez plus tard.", http.StatusTooManyRequests)
		return Mailbox{}, false
	}
	mailbox, err := s.store.Create()
	if errors.Is(err, errTooManyMailboxes) {
		http.Error(w, "Service saturé, réessayez plus tard.", http.StatusServiceUnavailable)
		return mailbox, false
	}
	if err != nil {
		serverError(w, "creating mailbox", err)
		return mailbox, false
	}
	return mailbox, true
}

// upload receives an .eml or .msg file (form field "file") and shows its
// analysis. POST /upload creates a mailbox, POST /inbox/{token}/upload adds
// the file to an existing one.
func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadSize+1<<20)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	var filename string
	var data []byte
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		if part.FormName() == "file" {
			filename = part.FileName()
			data, err = io.ReadAll(io.LimitReader(part, s.maxUploadSize+1))
			if err != nil {
				http.Error(w, "Envoi interrompu.", http.StatusBadRequest)
				return
			}
			break
		}
	}
	switch {
	case len(data) == 0:
		http.Error(w, "Aucun fichier reçu.", http.StatusBadRequest)
		return
	case int64(len(data)) > s.maxUploadSize:
		http.Error(w, "Fichier trop volumineux.", http.StatusRequestEntityTooLarge)
		return
	}
	if _, err := uploadedMail(filename, data); err != nil {
		http.Error(w, "Ce fichier n'est pas un mail : envoyez un fichier .eml ou .msg.", http.StatusUnprocessableEntity)
		return
	}

	token := r.PathValue("token")
	if token == "" {
		mailbox, ok := s.createMailbox(w, r)
		if !ok {
			return
		}
		token = mailbox.Token
	} else if !s.limiter.allow(s.clientIP(r)) {
		http.Error(w, "Trop de demandes, réessayez plus tard.", http.StatusTooManyRequests)
		return
	}
	id, err := s.store.AddUpload(token, filename, data, s.clientIP(r))
	if errors.Is(err, errNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		serverError(w, "storing upload", err)
		return
	}
	http.Redirect(w, r, "/inbox/"+token+"/"+id+"/1", http.StatusSeeOther)
}

type inboxItem struct {
	Link     string
	Filename string
	Format   string
	From     string
	Subject  string
	Date     string
}

type inboxSubmission struct {
	Received string
	Upload   bool
	MailFrom string
	Error    string
	Items    []inboxItem
}

func (s *server) inbox(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	mailbox, ok := s.store.ByToken(token)
	if !ok {
		http.NotFound(w, r)
		return
	}
	submissions, err := s.store.Submissions(token)
	if err != nil {
		serverError(w, "listing submissions", err)
		return
	}

	data := struct {
		Title       string
		Token       string
		Address     string
		Expires     string
		Submissions []inboxSubmission
	}{Title: "Boîte " + mailbox.Address, Token: token, Address: mailbox.Address, Expires: formatTime(mailbox.Expires)}
	for _, submission := range submissions {
		item := inboxSubmission{
			Received: formatTime(submission.Envelope.Received),
			Upload:   submission.Envelope.Mode == modeUpload,
			MailFrom: submission.Envelope.MailFrom,
			Error:    submission.Error,
		}
		for _, info := range submission.Analyzed {
			item.Items = append(item.Items, inboxItem{
				Link:     "/inbox/" + token + "/" + submission.ID + "/" + strconv.Itoa(info.N),
				Filename: info.Filename,
				Format:   info.Format,
				From:     info.From,
				Subject:  info.Subject,
				Date:     info.Date,
			})
		}
		data.Submissions = append(data.Submissions, item)
	}
	s.render(w, "inbox.html", data)
}

// analysis displays an extracted mail: header, parts and attachments, the
// selected part (?part=key) being shown in a sandboxed frame.
func (s *server) analysis(w http.ResponseWriter, r *http.Request) {
	mail, info, base, ok := s.lookupAnalyzed(w, r)
	if !ok {
		return
	}
	data := struct {
		Title       string
		Inbox       string
		Info        AnalyzedInfo
		Header      mailtoolkit.Header
		Parts       []Href
		Attachments []attachmentView
		Frame       string
		Links       []Link
		Dangers     int
		Warnings    int
		Auth        *headerAnalysis
		Part        string
	}{
		Title: "Analyse : " + info.Filename,
		Inbox: "/inbox/" + r.PathValue("token"),
		Info:  info,
		// Header stays empty for formats not parsed yet (.msg).
		Header: mail.Header,
	}

	keys := contentKeys(mail.Contents)
	selected := r.URL.Query().Get("part")
	if _, ok := mail.Contents[selected]; !ok {
		selected = defaultPart(mail.Contents, keys)
	}
	data.Part = selected
	for _, key := range keys {
		ct := mail.Contents[key].ContentInfo.Type
		data.Parts = append(data.Parts, Href{"?part=" + url.QueryEscape(key), ct.Type + "/" + ct.Subtype, key == selected})
	}
	if selected != "" {
		data.Frame = base + "/part/" + url.PathEscape(selected)
	}
	for _, name := range sortedKeys(mail.Attachments) {
		attachment := mail.Attachments[name]
		view := attachmentView{Link: base + "/attachment/" + url.PathEscape(name)}
		content, err := attachment.Decode()
		if err != nil {
			log.Printf("decoding attachment %s: %v", name, err)
		}
		ct := attachment.ContentInfo.Type
		view.Report = filecheck.Analyze(name, ct.Type+"/"+ct.Subtype, content)
		data.Attachments = append(data.Attachments, view)
	}
	sort.SliceStable(data.Attachments, func(i, j int) bool {
		return severity[data.Attachments[i].Level()] < severity[data.Attachments[j].Level()]
	})

	// Most suspicious links first, then in order of appearance.
	data.Links = extractLinks(mail)
	sort.SliceStable(data.Links, func(i, j int) bool {
		return severity[data.Links[i].Level()] < severity[data.Links[j].Level()]
	})
	for _, link := range data.Links {
		switch link.Level() {
		case levelDanger:
			data.Dangers++
		case levelWarning:
			data.Warnings++
		}
	}
	hop, err := strconv.Atoi(r.URL.Query().Get("hop"))
	if err != nil {
		hop = -1
	}
	auth, err := s.headerAnalysis(r, hop)
	if err != nil {
		serverError(w, "analyzing headers", err)
		return
	}
	auth.Part = selected
	auth.Converted = info.Format == formatMSG
	data.Auth = &auth
	s.render(w, "mail.html", data)
}

// headerAnalysis returns the cached analysis of the headers of the mail of
// /inbox/{token}/{id}/{n}, using the given Received hop for SPF.
func (s *server) headerAnalysis(r *http.Request, hop int) (headerAnalysis, error) {
	token, id, n := r.PathValue("token"), r.PathValue("id"), r.PathValue("n")
	key := token + "/" + id + "/" + n + "/" + strconv.Itoa(hop)
	if a, ok := s.auth.get(key); ok {
		return a, nil
	}
	number, _ := strconv.Atoi(n)
	raw, _, err := s.store.AnalyzedRaw(token, id, number)
	if err != nil {
		return headerAnalysis{}, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), dnsTimeout)
	defer cancel()
	a := analyzeHeaders(ctx, s.resolver, raw, hop)
	s.auth.put(key, a)
	return a, nil
}

// severity orders the alert levels, most severe first.
var severity = map[string]int{levelDanger: 0, levelWarning: 1, levelInfo: 2, "": 3}

// attachmentView is an analyzed attachment and its download link.
type attachmentView struct {
	filecheck.Report
	Link string
}

// defaultPart prefers the HTML version of a mail, then the plain text one.
func defaultPart(contents map[string]mailtoolkit.Content, keys []string) string {
	for _, subtype := range []string{"html", "plain"} {
		for _, key := range keys {
			ct := contents[key].ContentInfo.Type
			if ct.Type == "text" && ct.Subtype == subtype {
				return key
			}
		}
	}
	if len(keys) > 0 {
		return keys[0]
	}
	return ""
}

func (s *server) mailPart(w http.ResponseWriter, r *http.Request) {
	mail, _, _, ok := s.lookupAnalyzed(w, r)
	if !ok {
		return
	}
	content, ok := mail.Contents[r.PathValue("content")]
	if !ok {
		http.NotFound(w, r)
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
	mail, _, _, ok := s.lookupAnalyzed(w, r)
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

	// Attachments may be malicious: always downloaded, never displayed.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Security-Policy", mailCSP)
	w.Write(data)
}

// lookupAnalyzed returns the mail of /inbox/{token}/{id}/{n} and the base URL
// of its parts, or writes the error response.
func (s *server) lookupAnalyzed(w http.ResponseWriter, r *http.Request) (mailtoolkit.Mail, AnalyzedInfo, string, bool) {
	token, id := r.PathValue("token"), r.PathValue("id")
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		http.NotFound(w, r)
		return mailtoolkit.Mail{}, AnalyzedInfo{}, "", false
	}
	mail, info, err := s.store.Analyzed(token, id, n)
	if errors.Is(err, errNotFound) {
		http.NotFound(w, r)
		return mail, info, "", false
	}
	if errors.Is(err, errUnreadable) {
		log.Printf("reading mail: %v", err)
		http.Error(w, "Ce fichier Outlook .msg est endommagé ou dans un format non pris en charge.", http.StatusUnprocessableEntity)
		return mail, info, "", false
	}
	if err != nil {
		serverError(w, "reading mail", err)
		return mail, info, "", false
	}
	return mail, info, "/inbox/" + token + "/" + id + "/" + strconv.Itoa(n), true
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

func formatTime(t time.Time) string {
	return t.Local().Format("02.01.2006 15:04:05 MST")
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

// rateLimiter allows a number of events per key over a sliding window.
type rateLimiter struct {
	limit  int
	window time.Duration

	mu     sync.Mutex
	events map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, events: make(map[string][]time.Time)}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := l.events[key][:0]
	for _, t := range l.events[key] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.limit {
		l.events[key] = recent
		return false
	}
	l.events[key] = append(recent, now)
	return true
}

// prune forgets the keys without recent events.
func (l *rateLimiter) prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for key, events := range l.events {
		if len(events) == 0 || now.Sub(events[len(events)-1]) >= l.window {
			delete(l.events, key)
		}
	}
}
