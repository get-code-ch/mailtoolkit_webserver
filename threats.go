package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// ThreatIntelConfig enables the threat databases. Each one needs a key;
// the environment variables MTK_ABUSECH_KEY, MTK_SAFEBROWSING_KEY and
// MTK_VIRUSTOTAL_KEY override the file. Only host names, file hashes and,
// for the links of shared platforms, URLs without their parameters are
// sent.
type ThreatIntelConfig struct {
	// AbuseCHKey queries URLhaus (malware download sites) and
	// MalwareBazaar (malware files); a free abuse.ch account gives it.
	AbuseCHKey string `json:"abusech_key"`
	// SafeBrowsingKey queries Google Safe Browsing (phishing and malware
	// sites), free for non-commercial use.
	SafeBrowsingKey string `json:"safebrowsing_key"`
	// VirusTotalKey queries VirusTotal for the files and the domains; the
	// free key allows 4 queries a minute.
	VirusTotalKey string `json:"virustotal_key"`
}

func (c ThreatIntelConfig) enabled() bool {
	return c.AbuseCHKey != "" || c.SafeBrowsingKey != "" || c.VirusTotalKey != ""
}

// threatReport is what the threat databases know of the links and
// attachments of a mail.
type threatReport struct {
	Findings []threatFinding
	// Services are the databases queried, Errors those that failed.
	Services []string
	Errors   []string
	// Lookups tell what each database was asked, in the order of Services.
	Lookups []serviceLookup
}

// serviceLookup is what an external service was asked about a mail, and
// how it answered.
type serviceLookup struct {
	Service  string
	Subjects []string
	// Found counts the subjects known to the service, Failed the queries
	// left without answer.
	Found, Failed int
}

// lookup returns the record of a service, created on first use.
func lookupOf(lookups *[]serviceLookup, service string) *serviceLookup {
	for i := range *lookups {
		if (*lookups)[i].Service == service {
			return &(*lookups)[i]
		}
	}
	*lookups = append(*lookups, serviceLookup{Service: service})
	return &(*lookups)[len(*lookups)-1]
}

// add records the subjects of a query.
func (l *serviceLookup) add(subjects ...string) {
	for _, s := range subjects {
		if !slices.Contains(l.Subjects, s) {
			l.Subjects = append(l.Subjects, s)
		}
	}
}

// threatFinding is a link host, a URL or a file known to a database.
type threatFinding struct {
	Subject string
	// Kind is "lien" or "pièce jointe".
	Kind    string
	Service string
	Threat  string
	Level   string
	// Reference is the page of the database about the subject.
	Reference string
}

// threatSubjects are what a mail asks the databases about.
type threatSubjects struct {
	// Hosts are link hosts, URLs links on shared platforms, without query.
	Hosts []string
	URLs  []string
	Files []threatFile
}

type threatFile struct {
	Name, SHA256 string
}

// Bounds of the lookups of one mail.
const (
	maxThreatHosts = 12
	maxThreatURLs  = 20
	maxThreatFiles = 5
	// maxVirusTotal bounds the VirusTotal queries per mail (free quota of
	// 4 a minute).
	maxVirusTotal  = 4
	threatCacheTTL = 6 * time.Hour
)

// threatChecker queries the configured databases, caching the answers.
type threatChecker struct {
	config ThreatIntelConfig
	client *http.Client
	// Endpoints, replaced by the tests.
	urlhaus, bazaar, safeBrowsing, virusTotal string

	mu    sync.Mutex
	cache map[string]cachedThreat
}

type cachedThreat struct {
	findings []threatFinding
	expires  time.Time
}

func newThreatChecker(c ThreatIntelConfig) *threatChecker {
	if !c.enabled() {
		return nil
	}
	return &threatChecker{
		config:       c,
		client:       &http.Client{Timeout: 8 * time.Second},
		urlhaus:      "https://urlhaus-api.abuse.ch/v1/",
		bazaar:       "https://mb-api.abuse.ch/api/v1/",
		safeBrowsing: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
		virusTotal:   "https://www.virustotal.com/api/v3/",
		cache:        map[string]cachedThreat{},
	}
}

// subjectsOf chooses what to look up: the hosts of the links (suspicious
// first, as ordered by linkSubjects), the URLs of the links on shared
// platforms (a host such as sharepoint.com or github.com is always listed
// somewhere), and the attachments.
func subjectsOf(links []Link, attachments []attachmentView) threatSubjects {
	var s threatSubjects
	ordered := slices.Clone(links)
	slices.SortStableFunc(ordered, func(a, b Link) int { return spamSeverity[b.Level()] - spamSeverity[a.Level()] })
	for _, l := range ordered {
		host := linkHost(l.URL)
		if host == "" || strings.HasPrefix(strings.ToLower(l.URL), "mailto:") {
			continue
		}
		if sharedPlatform(host) {
			if u, err := url.Parse(l.URL); err == nil {
				u.RawQuery, u.Fragment = "", ""
				if !slices.Contains(s.URLs, u.String()) && len(s.URLs) < maxThreatURLs {
					s.URLs = append(s.URLs, u.String())
				}
			}
			continue
		}
		if !slices.Contains(s.Hosts, host) && len(s.Hosts) < maxThreatHosts {
			s.Hosts = append(s.Hosts, host)
		}
	}
	for _, a := range attachments {
		if len(s.Files) < maxThreatFiles {
			s.Files = append(s.Files, threatFile{a.Name, a.SHA256})
		}
	}
	return s
}

// sharedPlatform reports a host whose pages belong to many people: sharing
// and hosting services, trackers, and the domains of the big brands.
func sharedPlatform(host string) bool {
	if platformOf(sharingPlatforms, host) != "" || platformOf(hostingPlatforms, host) != "" || trackerOf(host) != "" {
		return true
	}
	org := mailauth.OrgDomain(host)
	return officialHost(host, brands) || official(org, brands...) || slices.Contains([]string{"github.com",
		"githubusercontent.com", "gitlab.com", "bitbucket.org", "discord.com", "discordapp.com", "telegram.org", "t.me"}, org)
}

// check queries every configured database, in parallel.
func (t *threatChecker) check(ctx context.Context, s threatSubjects) threatReport {
	var report threatReport
	if t == nil {
		return report
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	run := func(service, key string, subjects []string, lookup func() ([]threatFinding, error)) {
		if !slices.Contains(report.Services, service) {
			report.Services = append(report.Services, service)
		}
		lookupOf(&report.Lookups, service).add(subjects...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, err := t.cached(service+"\x00"+key, lookup)
			mu.Lock()
			defer mu.Unlock()
			l := lookupOf(&report.Lookups, service)
			if err != nil {
				l.Failed++
				if !slices.Contains(report.Errors, service) {
					report.Errors = append(report.Errors, service)
				}
				return
			}
			l.Found += len(findings)
			report.Findings = append(report.Findings, findings...)
		}()
	}
	if t.config.AbuseCHKey != "" {
		for _, h := range s.Hosts {
			run("URLhaus", h, []string{h}, func() ([]threatFinding, error) { return t.urlhausHost(ctx, h) })
		}
		for _, u := range s.URLs {
			run("URLhaus", u, []string{u}, func() ([]threatFinding, error) { return t.urlhausURL(ctx, u) })
		}
		for _, f := range s.Files {
			run("MalwareBazaar", f.SHA256, []string{f.Name}, func() ([]threatFinding, error) { return t.malwareBazaar(ctx, f) })
		}
	}
	if t.config.SafeBrowsingKey != "" && len(s.Hosts)+len(s.URLs) > 0 {
		var urls []string
		for _, h := range s.Hosts {
			urls = append(urls, "http://"+h+"/")
		}
		urls = append(urls, s.URLs...)
		run("Google Safe Browsing", strings.Join(urls, " "), append(slices.Clone(s.Hosts), s.URLs...), func() ([]threatFinding, error) { return t.safeBrowsingLookup(ctx, urls) })
	}
	if t.config.VirusTotalKey != "" {
		budget := maxVirusTotal
		for _, f := range s.Files {
			if budget > 0 {
				budget--
				run("VirusTotal", "file:"+f.SHA256, []string{f.Name}, func() ([]threatFinding, error) {
					return t.virusTotalLookup(ctx, "files/"+f.SHA256, f.Name, "pièce jointe", "https://www.virustotal.com/gui/file/"+f.SHA256)
				})
			}
		}
		seen := map[string]bool{}
		for _, h := range s.Hosts {
			org := mailauth.OrgDomain(h)
			if budget > 0 && org != "" && !seen[org] {
				budget--
				seen[org] = true
				run("VirusTotal", "domain:"+org, []string{org}, func() ([]threatFinding, error) {
					return t.virusTotalLookup(ctx, "domains/"+org, org, "lien", "https://www.virustotal.com/gui/domain/"+org)
				})
			}
		}
	}
	wg.Wait()
	slices.SortStableFunc(report.Findings, func(a, b threatFinding) int { return spamSeverity[b.Level] - spamSeverity[a.Level] })
	return report
}

// cached returns the cached answer of a lookup, or runs it. Errors are not
// cached.
func (t *threatChecker) cached(key string, lookup func() ([]threatFinding, error)) ([]threatFinding, error) {
	t.mu.Lock()
	if c, ok := t.cache[key]; ok && time.Now().Before(c.expires) {
		t.mu.Unlock()
		return c.findings, nil
	}
	t.mu.Unlock()
	findings, err := lookup()
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.cache) > 10000 {
		clear(t.cache)
	}
	t.cache[key] = cachedThreat{findings, time.Now().Add(threatCacheTTL)}
	return findings, nil
}

// do sends a request and decodes a JSON answer; a 404 is "not found".
func (t *threatChecker) do(req *http.Request, v any) (found bool, err error) {
	req.Header.Set("User-Agent", "mailtoolkit_webserver (mail analysis)")
	resp, err := t.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("réponse %s", resp.Status)
	}
	return true, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

func (t *threatChecker) postForm(ctx context.Context, endpoint string, form url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", t.config.AbuseCHKey)
	_, err = t.do(req, v)
	return err
}

// urlhausAnswer is the answer of the URLhaus host and URL endpoints.
type urlhausAnswer struct {
	Status    string `json:"query_status"`
	Reference string `json:"urlhaus_reference"`
	// Host endpoint: the malicious URLs of the host.
	URLs []struct {
		Status string `json:"url_status"`
		Threat string `json:"threat"`
	} `json:"urls"`
	// URL endpoint.
	URLStatus string `json:"url_status"`
	Threat    string `json:"threat"`
}

func (t *threatChecker) urlhausHost(ctx context.Context, host string) ([]threatFinding, error) {
	var a urlhausAnswer
	if err := t.postForm(ctx, t.urlhaus+"host/", url.Values{"host": {host}}, &a); err != nil {
		return nil, err
	}
	if a.Status != "ok" || len(a.URLs) == 0 {
		return nil, abuseCHStatus(a.Status)
	}
	online, threat := 0, a.URLs[0].Threat
	for _, u := range a.URLs {
		if u.Status == "online" {
			online++
		}
	}
	f := threatFinding{Subject: host, Kind: "lien", Service: "URLhaus", Level: levelWarning, Reference: a.Reference,
		Threat: fmt.Sprintf("%s, %d adresse%s malveillante%s répertoriée%s", threatName(threat), len(a.URLs), plural(len(a.URLs)), plural(len(a.URLs)), plural(len(a.URLs)))}
	if online > 0 {
		f.Level = levelDanger
		f.Threat += fmt.Sprintf(", dont %d encore active%s", online, plural(online))
	}
	return []threatFinding{f}, nil
}

func (t *threatChecker) urlhausURL(ctx context.Context, u string) ([]threatFinding, error) {
	var a urlhausAnswer
	if err := t.postForm(ctx, t.urlhaus+"url/", url.Values{"url": {u}}, &a); err != nil {
		return nil, err
	}
	if a.Status != "ok" {
		return nil, abuseCHStatus(a.Status)
	}
	level := levelWarning
	if a.URLStatus == "online" {
		level = levelDanger
	}
	return []threatFinding{{Subject: u, Kind: "lien", Service: "URLhaus", Threat: threatName(a.Threat), Level: level, Reference: a.Reference}}, nil
}

func (t *threatChecker) malwareBazaar(ctx context.Context, f threatFile) ([]threatFinding, error) {
	var a struct {
		Status string `json:"query_status"`
		Data   []struct {
			Signature string `json:"signature"`
			FileType  string `json:"file_type"`
		} `json:"data"`
	}
	if err := t.postForm(ctx, t.bazaar, url.Values{"query": {"get_info"}, "hash": {f.SHA256}}, &a); err != nil {
		return nil, err
	}
	if a.Status != "ok" || len(a.Data) == 0 {
		return nil, abuseCHStatus(a.Status)
	}
	threat := "logiciel malveillant connu"
	if a.Data[0].Signature != "" {
		threat += " (" + a.Data[0].Signature + ")"
	}
	return []threatFinding{{Subject: f.Name, Kind: "pièce jointe", Service: "MalwareBazaar", Threat: threat, Level: levelDanger,
		Reference: "https://bazaar.abuse.ch/sample/" + f.SHA256 + "/"}}, nil
}

// abuseCHStatus turns the query status of abuse.ch into an error, nil for
// "not found".
func abuseCHStatus(status string) error {
	switch status {
	case "ok", "no_results", "hash_not_found", "illegal_hash", "invalid_url", "invalid_host":
		return nil
	}
	return errors.New(status)
}

func (t *threatChecker) safeBrowsingLookup(ctx context.Context, urls []string) ([]threatFinding, error) {
	entries := make([]map[string]string, len(urls))
	for i, u := range urls {
		entries[i] = map[string]string{"url": u}
	}
	body, _ := json.Marshal(map[string]any{
		"client": map[string]string{"clientId": "mailtoolkit_webserver", "clientVersion": "1.6"},
		"threatInfo": map[string]any{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    entries,
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.safeBrowsing+"?key="+url.QueryEscape(t.config.SafeBrowsingKey), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var a struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
			Threat     struct {
				URL string `json:"url"`
			} `json:"threat"`
		} `json:"matches"`
	}
	if _, err := t.do(req, &a); err != nil {
		return nil, err
	}
	var findings []threatFinding
	for _, m := range a.Matches {
		subject := m.Threat.URL
		if u, err := url.Parse(subject); err == nil && (u.Path == "/" || u.Path == "") {
			subject = u.Host
		}
		findings = append(findings, threatFinding{Subject: subject, Kind: "lien", Service: "Google Safe Browsing",
			Threat: threatName(m.ThreatType), Level: levelDanger,
			Reference: "https://transparencyreport.google.com/safe-browsing/search?url=" + url.QueryEscape(m.Threat.URL)})
	}
	return findings, nil
}

func (t *threatChecker) virusTotalLookup(ctx context.Context, path, subject, kind, reference string) ([]threatFinding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.virusTotal+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", t.config.VirusTotalKey)
	var a struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	found, err := t.do(req, &a)
	if err != nil || !found {
		return nil, err
	}
	stats := a.Data.Attributes.Stats
	f := threatFinding{Subject: subject, Kind: kind, Service: "VirusTotal", Reference: reference,
		Threat: fmt.Sprintf("%d antivirus le jugent malveillant, %d suspect", stats.Malicious, stats.Suspicious)}
	switch {
	case stats.Malicious >= 3:
		f.Level = levelDanger
	case stats.Malicious >= 1 || stats.Suspicious >= 2:
		f.Level = levelWarning
	default:
		return nil, nil
	}
	return []threatFinding{f}, nil
}

// threatName translates the threat types of the databases.
func threatName(t string) string {
	switch strings.ToLower(t) {
	case "malware_download", "malware":
		return "distribution de logiciels malveillants"
	case "social_engineering", "phishing":
		return "hameçonnage"
	case "unwanted_software":
		return "logiciel indésirable"
	case "potentially_harmful_application":
		return "application potentiellement dangereuse"
	case "":
		return "menace"
	}
	return t
}

func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}

// assessThreats reports the links and files known to a database.
func assessThreats(r *riskReport, report threatReport, add func(level string, weight int, anchor, simple, detail string)) {
	for _, f := range report.Findings {
		detail := f.Service + " : " + f.Threat
		file := f.Kind == "pièce jointe"
		switch {
		case f.Level == levelDanger && file:
			add(levelDanger, 4, "threats", fmt.Sprintf("La pièce jointe « %s » est un logiciel malveillant connu de %s : ne l'ouvrez surtout pas.",
				f.Subject, f.Service), detail)
		case f.Level == levelDanger:
			add(levelDanger, 4, "threats", fmt.Sprintf("Le site %s est répertorié comme malveillant par %s (%s).", f.Subject, f.Service, f.Threat), detail)
		case file:
			add(levelWarning, 1, "threats", fmt.Sprintf("La pièce jointe « %s » est signalée par %s.", f.Subject, f.Service), detail)
		default:
			add(levelWarning, 1, "threats", fmt.Sprintf("Le site %s est signalé par %s.", f.Subject, f.Service), detail)
		}
	}
	if len(report.Services) > 0 && len(report.Findings) == 0 && len(report.Errors) == 0 {
		r.Positives = append(r.Positives, "Aucun lien ni aucune pièce jointe n'est connu des bases de menaces consultées ("+
			strings.Join(report.Services, ", ")+").")
	}
}
