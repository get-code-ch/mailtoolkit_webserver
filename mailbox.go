package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/smtpd"
)

var (
	errNotFound         = errors.New("not found")
	errTooManyMailboxes = errors.New("too many active mailboxes")
	errNoAttachedMail   = "no attached mail found"
	// errUnreadable is returned for a .msg file that cannot be read.
	errUnreadable        = errors.New("unreadable mail")
	lowerBase32          = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	maxParsedCachedMails = 32
)

// Mailbox is a random address, readable through its secret token for a
// limited time.
type Mailbox struct {
	Token   string    `json:"token"`
	Address string    `json:"address"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// Submission is a carrier mail received by a mailbox and the mails
// extracted from it.
type Submission struct {
	ID       string         `json:"id"`
	Envelope smtpd.Envelope `json:"-"`
	Analyzed []AnalyzedInfo `json:"analyzed"`
	// Error explains why no mail, or not every mail, could be extracted.
	Error string `json:"error,omitempty"`
}

// AnalyzedInfo describes an extracted mail.
type AnalyzedInfo struct {
	N        int    `json:"n"`
	Filename string `json:"filename"`
	Format   string `json:"format"`
	File     string `json:"file"`
	From     string `json:"from,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Date     string `json:"date,omitempty"`
}

// mailboxStore keeps the mailboxes on disk, one folder per token:
//
//	<token>/mailbox.json
//	<token>/<id>/carrier.eml, envelope.json, analyzed-<n>.<format>, result.json
//
// result.json is written last, a submission without it is ignored. The
// store implements smtpd.Backend and is safe for concurrent use.
type mailboxStore struct {
	root         *os.Root
	domains      map[string]bool
	domain       string
	retention    time.Duration
	maxMailboxes int
	now          func() time.Time

	mu        sync.RWMutex
	byToken   map[string]Mailbox
	byAddress map[string]string

	// parsed keeps the last parsed mails: the analysis page and its frames
	// parse the same mail several times.
	parsed *boundedCache[mailtoolkit.Mail]
}

func newMailboxStore(folder string, domains []string, retention time.Duration, maxMailboxes int) (*mailboxStore, error) {
	return newMailboxStoreClock(folder, domains, retention, maxMailboxes, time.Now)
}

// newMailboxStoreClock is newMailboxStore with a clock, for tests.
func newMailboxStoreClock(folder string, domains []string, retention time.Duration, maxMailboxes int, now func() time.Time) (*mailboxStore, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domain configured")
	}
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, err
	}
	s := &mailboxStore{
		root:         root,
		domains:      make(map[string]bool),
		domain:       strings.ToLower(domains[0]),
		retention:    retention,
		maxMailboxes: maxMailboxes,
		now:          now,
		byToken:      make(map[string]Mailbox),
		byAddress:    make(map[string]string),
		parsed:       newBoundedCache[mailtoolkit.Mail](maxParsedCachedMails),
	}
	for _, d := range domains {
		s.domains[strings.ToLower(d)] = true
	}
	return s, s.load()
}

// load indexes the mailboxes found on disk and removes the expired ones.
func (s *mailboxStore) load() error {
	entries, err := fs.ReadDir(s.root.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validToken(entry.Name()) {
			continue
		}
		var mailbox Mailbox
		if err := s.readJSON(entry.Name()+"/mailbox.json", &mailbox); err != nil || mailbox.Token != entry.Name() {
			log.Printf("mailbox %s: unreadable, ignored: %v", entry.Name(), err)
			continue
		}
		if !s.now().Before(mailbox.Expires) {
			s.remove(mailbox.Token)
			continue
		}
		s.byToken[mailbox.Token] = mailbox
		s.byAddress[mailbox.Address] = mailbox.Token
	}
	return nil
}

// Create returns a new mailbox with a random address and token.
func (s *mailboxStore) Create() (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	active := 0
	for _, mailbox := range s.byToken {
		if now.Before(mailbox.Expires) {
			active++
		}
	}
	if s.maxMailboxes > 0 && active >= s.maxMailboxes {
		return Mailbox{}, errTooManyMailboxes
	}

	mailbox := Mailbox{Token: randomString(16), Created: now.UTC(), Expires: now.Add(s.retention).UTC()}
	for {
		// 10 base32 characters: 50 random bits
		mailbox.Address = randomString(7)[:10] + "@" + s.domain
		if _, used := s.byAddress[mailbox.Address]; !used {
			break
		}
	}

	if err := s.root.Mkdir(mailbox.Token, 0o700); err != nil {
		return Mailbox{}, err
	}
	if err := s.writeJSON(mailbox.Token+"/mailbox.json", mailbox); err != nil {
		s.root.RemoveAll(mailbox.Token)
		return Mailbox{}, err
	}
	s.byToken[mailbox.Token] = mailbox
	s.byAddress[mailbox.Address] = mailbox.Token
	return mailbox, nil
}

// ByToken returns an active mailbox.
func (s *mailboxStore) ByToken(token string) (Mailbox, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mailbox, ok := s.byToken[token]
	if !ok || !s.now().Before(mailbox.Expires) {
		return Mailbox{}, false
	}
	return mailbox, true
}

func (s *mailboxStore) byAddressToken(address string) (string, bool) {
	s.mu.RLock()
	token, ok := s.byAddress[address]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	_, ok = s.ByToken(token)
	return token, ok
}

// ValidRecipient implements smtpd.Backend: only active mailboxes of our
// domains receive mail.
func (s *mailboxStore) ValidRecipient(address string) bool {
	_, domain, _ := strings.Cut(address, "@")
	if !s.domains[domain] {
		return false
	}
	_, ok := s.byAddressToken(address)
	return ok
}

// Deliver implements smtpd.Backend: the carrier is stored in each
// recipient mailbox with the mails extracted from it.
func (s *mailboxStore) Deliver(env smtpd.Envelope, data []byte) error {
	delivered := map[string]bool{}
	for _, address := range env.Recipients {
		token, ok := s.byAddressToken(address)
		if !ok || delivered[token] {
			continue
		}
		if err := s.deliverTo(token, env, data); err != nil {
			return fmt.Errorf("mailbox %s: %w", address, err)
		}
		delivered[token] = true
	}
	return nil
}

func (s *mailboxStore) deliverTo(token string, env smtpd.Envelope, carrier []byte) error {
	mails, err := extractMails(carrier)
	var problem string
	if err != nil {
		problem = "carrier mail partially read: " + err.Error()
	}
	return s.writeSubmission(token, env, carrier, mails, problem)
}

// AddUpload stores an uploaded .eml or .msg file as a new submission and
// returns its id.
func (s *mailboxStore) AddUpload(token, filename string, data []byte, remoteIP string) (string, error) {
	if _, ok := s.ByToken(token); !ok {
		return "", errNotFound
	}
	mail, err := uploadedMail(filename, data)
	if err != nil {
		return "", err
	}
	env := smtpd.Envelope{ID: smtpd.NewID(), Mode: modeUpload, RemoteAddr: remoteIP, Received: s.now().UTC()}
	return env.ID, s.writeSubmission(token, env, nil, []extractedMail{mail}, "")
}

// writeSubmission stores a submission: the carrier mail (none for an
// upload), its envelope and the mails to analyze. result.json is written
// last, the submission is ignored until then.
func (s *mailboxStore) writeSubmission(token string, env smtpd.Envelope, carrier []byte, mails []extractedMail, problem string) error {
	dir := token + "/" + env.ID
	if err := s.root.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if carrier != nil {
		if err := s.writeFile(dir+"/carrier.eml", carrier); err != nil {
			return err
		}
	}
	if err := s.writeJSON(dir+"/envelope.json", env); err != nil {
		return err
	}

	submission := Submission{ID: env.ID, Analyzed: []AnalyzedInfo{}, Error: problem}
	for i, mail := range mails {
		info := AnalyzedInfo{
			N:        i + 1,
			Filename: mail.Filename,
			Format:   mail.Format,
			File:     fmt.Sprintf("analyzed-%d.%s", i+1, mail.Format),
		}
		if eml, err := toEML(mail.Format, mail.Data); err == nil {
			if header, err := mailtoolkit.ParseHeader(eml); err == nil {
				info.From, info.Subject, info.Date = header.From, header.Subject, header.Date
			}
		}
		if err := s.writeFile(dir+"/"+info.File, mail.Data); err != nil {
			return err
		}
		submission.Analyzed = append(submission.Analyzed, info)
	}
	if len(mails) == 0 && submission.Error == "" {
		submission.Error = errNoAttachedMail
	}
	return s.writeJSON(dir+"/result.json", submission)
}

// Submissions lists the carriers received by a mailbox, newest first.
func (s *mailboxStore) Submissions(token string) ([]Submission, error) {
	if _, ok := s.ByToken(token); !ok {
		return nil, errNotFound
	}
	entries, err := fs.ReadDir(s.root.FS(), token)
	if err != nil {
		return nil, err
	}
	submissions := []Submission{}
	for _, entry := range entries {
		if !entry.IsDir() || !validID(entry.Name()) {
			continue
		}
		submission, err := s.submission(token, entry.Name())
		if err != nil {
			continue // being delivered
		}
		submissions = append(submissions, submission)
	}
	sort.Slice(submissions, func(i, j int) bool {
		return submissions[i].Envelope.Received.After(submissions[j].Envelope.Received)
	})
	return submissions, nil
}

// Submission returns one carrier of an active mailbox.
func (s *mailboxStore) Submission(token, id string) (Submission, error) {
	if _, ok := s.ByToken(token); !ok || !validID(id) {
		return Submission{}, errNotFound
	}
	return s.submission(token, id)
}

func (s *mailboxStore) submission(token, id string) (Submission, error) {
	var submission Submission
	if err := s.readJSON(token+"/"+id+"/result.json", &submission); err != nil {
		return Submission{}, err
	}
	if err := s.readJSON(token+"/"+id+"/envelope.json", &submission.Envelope); err != nil {
		return Submission{}, err
	}
	return submission, nil
}

// analyzedInfo describes the n-th mail extracted from a carrier.
func (s *mailboxStore) analyzedInfo(token, id string, n int) (AnalyzedInfo, error) {
	submission, err := s.Submission(token, id)
	if errors.Is(err, fs.ErrNotExist) {
		err = errNotFound
	}
	if err != nil {
		return AnalyzedInfo{}, err
	}
	if n < 1 || n > len(submission.Analyzed) {
		return AnalyzedInfo{}, errNotFound
	}
	return submission.Analyzed[n-1], nil
}

// AnalyzedRaw returns the n-th mail extracted from a carrier, in the eml
// format: as received, or converted from Outlook .msg.
func (s *mailboxStore) AnalyzedRaw(token, id string, n int) ([]byte, AnalyzedInfo, error) {
	info, err := s.analyzedInfo(token, id, n)
	if err != nil {
		return nil, info, err
	}
	data, err := s.root.ReadFile(token + "/" + id + "/" + info.File)
	if err != nil {
		return nil, info, err
	}
	eml, err := toEML(info.Format, data)
	return eml, info, err
}

// Analyzed returns the n-th mail extracted from a carrier, parsed.
func (s *mailboxStore) Analyzed(token, id string, n int) (mailtoolkit.Mail, AnalyzedInfo, error) {
	info, err := s.analyzedInfo(token, id, n)
	if err != nil {
		return mailtoolkit.Mail{}, info, err
	}
	key := token + "/" + id + "/" + strconv.Itoa(n)
	if mail, ok := s.parsed.get(key); ok {
		return mail, info, nil
	}
	data, _, err := s.AnalyzedRaw(token, id, n)
	if err != nil {
		return mailtoolkit.Mail{}, info, err
	}
	mail, err := mailtoolkit.Parse(data)
	if err != nil {
		log.Printf("%s: %v", key, err)
	}
	s.parsed.put(key, mail)
	return mail, info, nil
}

// DeleteSubmission removes a carrier and the mails extracted from it.
func (s *mailboxStore) DeleteSubmission(token, id string) error {
	if _, err := s.Submission(token, id); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = errNotFound
		}
		return err
	}
	if err := s.root.RemoveAll(token + "/" + id); err != nil {
		return err
	}
	s.parsed.clear()
	return nil
}

// PurgeExpired removes the expired mailboxes and their mails.
func (s *mailboxStore) PurgeExpired() {
	now := s.now()
	var expired []string
	s.mu.Lock()
	for token, mailbox := range s.byToken {
		if !now.Before(mailbox.Expires) {
			expired = append(expired, token)
			delete(s.byToken, token)
			delete(s.byAddress, mailbox.Address)
		}
	}
	s.mu.Unlock()

	for _, token := range expired {
		s.remove(token)
	}
	if len(expired) > 0 {
		s.parsed.clear()
		log.Printf("purged %d expired mailboxes", len(expired))
	}
}

func (s *mailboxStore) remove(token string) {
	if err := s.root.RemoveAll(token); err != nil {
		log.Printf("mailbox %s: %v", token, err)
	}
}

// writeFile writes atomically: readers never see a partial file.
func (s *mailboxStore) writeFile(name string, data []byte) error {
	tmp := path.Join(path.Dir(name), "."+path.Base(name)+".tmp")
	if err := s.root.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return s.root.Rename(tmp, name)
}

func (s *mailboxStore) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(name, data)
}

func (s *mailboxStore) readJSON(name string, v any) error {
	data, err := s.root.ReadFile(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return lowerBase32.EncodeToString(b)
}

// validToken checks a token from a URL: 16 random bytes in base32.
func validToken(token string) bool {
	return len(token) == 26 && strings.Trim(token, "abcdefghijklmnopqrstuvwxyz234567") == ""
}

// validID checks a submission id: 12 random bytes in hex (smtpd.newID).
func validID(id string) bool {
	return len(id) == 24 && strings.Trim(id, "0123456789abcdef") == ""
}
