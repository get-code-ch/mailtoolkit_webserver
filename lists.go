package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// suggestionDomains returns the domains of a red mail the administrator may
// block: the sender's, those of the suspicious links and the lookalikes.
func suggestionDomains(risk riskReport, a *headerAnalysis, links []Link, lookalikes []lookalike) []string {
	if risk.Light != riskRed {
		return nil
	}
	var domains []string
	add := func(host string) {
		if org := mailauth.OrgDomain(strings.ToLower(host)); org != "" && !slices.Contains(domains, org) && !freemail(org) {
			domains = append(domains, org)
		}
	}
	if a != nil {
		add(a.FromDomain)
	}
	for _, l := range links {
		if lv := l.Level(); lv == levelDanger || lv == levelWarning {
			if h := linkHost(l.URL); platformOf(sharingPlatforms, h) == "" && platformOf(hostingPlatforms, h) == "" && trackerOf(h) == "" {
				add(h)
			} else if h != "" {
				domains = append(domains, h) // the page, not the platform
			}
		}
	}
	for _, l := range lookalikes {
		add(l.Domain)
	}
	return domains
}

// Local lists: domains, sender addresses and file hashes the organization
// marked as malicious or trusted, from the statistics page.
const (
	listsFile = "lists.json"
	maxListed = 5000

	listDomain = "domain"
	listSender = "sender"
	listHash   = "hash"

	verdictBlock = "block"
	verdictTrust = "trust"
)

// listEntry is a domain, an address or a SHA-256 hash, and its verdict.
type listEntry struct {
	Kind    string    `json:"kind"`
	Value   string    `json:"value"`
	Verdict string    `json:"verdict"`
	Note    string    `json:"note,omitempty"`
	Added   time.Time `json:"added"`
}

// KindText names the kind of an entry.
func (e listEntry) KindText() string {
	return map[string]string{listDomain: "domaine", listSender: "expéditeur", listHash: "fichier (SHA-256)"}[e.Kind]
}

// listStore keeps the lists in the data folder. It is safe for concurrent
// use.
type listStore struct {
	root *os.Root

	mu      sync.RWMutex
	entries []listEntry
}

func newListStore(folder string) (*listStore, error) {
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, err
	}
	s := &listStore{root: root}
	raw, err := root.ReadFile(listsFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.entries); err != nil {
			return nil, fmt.Errorf("%s: %w", listsFile, err)
		}
	}
	return s, nil
}

// normalizeEntry checks and normalizes a value of a kind.
func normalizeEntry(kind, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch kind {
	case listDomain:
		value = strings.Trim(strings.ToLower(value), ".")
		if u, ok := strings.CutPrefix(value, "http://"); ok {
			value = u
		} else if u, ok := strings.CutPrefix(value, "https://"); ok {
			value = u
		}
		value, _, _ = strings.Cut(value, "/")
		ascii, err := idna.Lookup.ToASCII(value)
		if err != nil || !strings.Contains(ascii, ".") {
			return "", errors.New("nom de domaine invalide")
		}
		return ascii, nil
	case listSender:
		a, err := mail.ParseAddress(value)
		if err != nil {
			return "", errors.New("adresse invalide")
		}
		return strings.ToLower(a.Address), nil
	case listHash:
		value = strings.ToLower(value)
		if b, err := hex.DecodeString(value); err != nil || len(b) != 32 {
			return "", errors.New("empreinte SHA-256 invalide (64 caractères hexadécimaux)")
		}
		return value, nil
	}
	return "", errors.New("type de liste inconnu")
}

// add records an entry, replacing the verdict of an existing one.
func (s *listStore) add(kind, value, verdict, note string) error {
	value, err := normalizeEntry(kind, value)
	if err != nil {
		return err
	}
	if verdict != verdictBlock && verdict != verdictTrust {
		return errors.New("verdict inconnu")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := listEntry{Kind: kind, Value: value, Verdict: verdict, Note: strings.TrimSpace(note), Added: time.Now().UTC()}
	if i := slices.IndexFunc(s.entries, func(e listEntry) bool { return e.Kind == kind && e.Value == value }); i >= 0 {
		s.entries[i] = entry
	} else {
		if len(s.entries) >= maxListed {
			return errors.New("listes pleines")
		}
		s.entries = append(s.entries, entry)
	}
	return s.save()
}

// remove deletes an entry.
func (s *listStore) remove(kind, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = slices.DeleteFunc(s.entries, func(e listEntry) bool { return e.Kind == kind && e.Value == value })
	return s.save()
}

// save writes the lists atomically; the lock is held.
func (s *listStore) save() error {
	raw, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	if err := s.root.WriteFile(listsFile+".tmp", raw, 0o600); err != nil {
		return err
	}
	return s.root.Rename(listsFile+".tmp", listsFile)
}

// all returns the entries, newest first.
func (s *listStore) all() []listEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := slices.Clone(s.entries)
	slices.SortStableFunc(entries, func(a, b listEntry) int { return b.Added.Compare(a.Added) })
	return entries
}

// localLists is a snapshot of the lists for one analysis.
type localLists struct {
	entries []listEntry
}

func (s *listStore) snapshot() localLists {
	return localLists{s.all()}
}

// domainVerdict returns the entry of a host or of one of its parents.
func (l localLists) domainVerdict(host string) (listEntry, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, e := range l.entries {
		if e.Kind == listDomain && (host == e.Value || strings.HasSuffix(host, "."+e.Value)) {
			return e, true
		}
	}
	return listEntry{}, false
}

func (l localLists) find(kind, value string) (listEntry, bool) {
	value = strings.ToLower(value)
	for _, e := range l.entries {
		if e.Kind == kind && e.Value == value {
			return e, true
		}
	}
	return listEntry{}, false
}

// trustedDomains are the domains marked as trusted.
func (l localLists) trustedDomains() []string {
	var domains []string
	for _, e := range l.entries {
		if e.Kind == listDomain && e.Verdict == verdictTrust {
			domains = append(domains, e.Value)
		}
	}
	return domains
}

// assessLists applies the local lists to a mail: blocked domains, senders
// and files are serious findings; a trusted sender authenticated by the
// receiving server is trusted like a trusted domain; a trusted file is not
// counted.
func assessLists(r *riskReport, l localLists, a *headerAnalysis, links []Link, add func(level string, weight int, anchor, simple, detail string)) {
	note := func(e listEntry) string {
		if e.Note != "" {
			return e.KindText() + " " + e.Value + " : " + e.Note
		}
		return e.KindText() + " " + e.Value
	}
	if a != nil {
		if e, ok := l.find(listSender, a.FromAddress); ok {
			if e.Verdict == verdictBlock {
				add(levelDanger, 4, "lists", fmt.Sprintf("L'expéditeur %s figure sur la liste noire de votre organisation.", a.FromAddress), note(e))
			} else if r.ProviderAuthenticated(a) {
				r.Trusted = true
				r.Positives = append(r.Positives, fmt.Sprintf("L'expéditeur %s figure sur la liste de confiance de votre organisation "+
					"et votre messagerie a confirmé son identité.", a.FromAddress))
			}
		}
		seen := map[string]bool{}
		for _, s := range a.Senders {
			if e, ok := l.domainVerdict(s.Value); ok && e.Verdict == verdictBlock && !seen[e.Value] {
				seen[e.Value] = true
				add(levelDanger, 4, "lists", fmt.Sprintf("Le domaine %s (%s) figure sur la liste noire de votre organisation.", s.Value, s.Role), note(e))
			}
		}
	}
	seen := map[string]bool{}
	for _, link := range links {
		host := linkHost(link.URL)
		if e, ok := l.domainVerdict(host); ok && e.Verdict == verdictBlock && !seen[host] {
			seen[host] = true
			add(levelDanger, 4, "lists", fmt.Sprintf("Un lien mène vers %s, sur la liste noire de votre organisation.", host), note(e)+" · "+link.URL)
		}
	}
}

// listedFile returns the verdict of an attachment.
func (l localLists) listedFile(sha256 string) (listEntry, bool) {
	return l.find(listHash, sha256)
}
