package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/get-code-ch/mailtoolkit_webserver/filecheck"
)

const evilSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fakeThreatServices answers like URLhaus, MalwareBazaar, Safe Browsing and
// VirusTotal, recording what they receive.
func fakeThreatServices(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.PostForm, _ = url.ParseQuery(string(body))
		mu.Lock()
		received = append(received, r.URL.Path+" "+string(body))
		mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/urlhaus/") && r.Header.Get("Auth-Key") != "abuse-key":
			w.Write([]byte(`{"query_status":"unknown_auth_key"}`))
		case r.URL.Path == "/urlhaus/host/" && r.PostForm.Get("host") == "malware.example":
			w.Write([]byte(`{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/malware.example/",
				"urls":[{"url_status":"online","threat":"malware_download"},{"url_status":"offline","threat":"malware_download"}]}`))
		case r.URL.Path == "/urlhaus/url/" && strings.Contains(r.PostForm.Get("url"), "sharepoint.com/sites/x/evil.zip"):
			w.Write([]byte(`{"query_status":"ok","url_status":"offline","threat":"malware_download","urlhaus_reference":"https://urlhaus.abuse.ch/url/1/"}`))
		case strings.HasPrefix(r.URL.Path, "/urlhaus/"):
			w.Write([]byte(`{"query_status":"no_results"}`))
		case r.URL.Path == "/bazaar/" && r.PostForm.Get("hash") == evilSHA:
			w.Write([]byte(`{"query_status":"ok","data":[{"signature":"AgentTesla","file_type":"exe"}]}`))
		case r.URL.Path == "/bazaar/":
			w.Write([]byte(`{"query_status":"hash_not_found"}`))
		case r.URL.Path == "/safebrowsing" && r.URL.Query().Get("key") == "sb-key":
			var req struct {
				ThreatInfo struct {
					Entries []struct{ URL string } `json:"threatEntries"`
				} `json:"threatInfo"`
			}
			json.Unmarshal(body, &req)
			for _, e := range req.ThreatInfo.Entries {
				if strings.Contains(e.URL, "login-portal.example") {
					w.Write([]byte(`{"matches":[{"threatType":"SOCIAL_ENGINEERING","threat":{"url":"` + e.URL + `"}}]}`))
					return
				}
			}
			w.Write([]byte(`{}`))
		case r.URL.Path == "/vt/domains/malware.example" && r.Header.Get("x-apikey") == "vt-key":
			w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"suspicious":1}}}}`))
		case r.URL.Path == "/vt/domains/quiet.example":
			w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &received
}

func newTestThreatChecker(server *httptest.Server, c ThreatIntelConfig) *threatChecker {
	checker := newThreatChecker(c)
	checker.urlhaus, checker.bazaar = server.URL+"/urlhaus/", server.URL+"/bazaar/"
	checker.safeBrowsing, checker.virusTotal = server.URL+"/safebrowsing", server.URL+"/vt/"
	return checker
}

func TestThreats(t *testing.T) {
	server, received := fakeThreatServices(t)
	checker := newTestThreatChecker(server, ThreatIntelConfig{AbuseCHKey: "abuse-key", SafeBrowsingKey: "sb-key", VirusTotalKey: "vt-key"})
	links := []Link{
		analyzeLink("https://malware.example/payload?user=victim@example.com", "", "lien", "text/html"),
		analyzeLink("https://login-portal.example/signin?id=42", "", "lien", "text/html"),
		analyzeLink("https://contoso.sharepoint.com/sites/x/evil.zip?download=1&u=victim", "", "pièce jointe", "a.pdf"),
		analyzeLink("https://quiet.example/", "", "lien", "text/html"),
		analyzeLink("mailto:someone@example.org", "", "lien", "text/html"),
	}
	attachments := []attachmentView{{Report: filecheck.Report{Name: "invoice.exe", SHA256: evilSHA}}}
	report := checker.check(context.Background(), subjectsOf(links, attachments))

	want := map[string]string{
		"URLhaus malware.example":                                 levelDanger,
		"URLhaus https://contoso.sharepoint.com/sites/x/evil.zip": levelWarning,
		"MalwareBazaar invoice.exe":                               levelDanger,
		"Google Safe Browsing login-portal.example":               levelDanger,
		"VirusTotal malware.example":                              levelDanger,
	}
	for _, f := range report.Findings {
		key := f.Service + " " + f.Subject
		if want[key] != f.Level {
			t.Errorf("unexpected %s: %s (%s)", key, f.Level, f.Threat)
		}
		delete(want, key)
	}
	if len(want) != 0 || len(report.Errors) != 0 {
		t.Errorf("missing %v, errors %v", want, report.Errors)
	}
	// Neither the parameters of the links nor the mailto addresses are
	// sent.
	for _, r := range *received {
		if strings.Contains(r, "victim") || strings.Contains(r, "someone") {
			t.Errorf("private data sent: %s", r)
		}
	}

	// Answers are cached.
	before := len(*received)
	checker.check(context.Background(), subjectsOf(links, attachments))
	if len(*received) != before {
		t.Errorf("%d queries repeated", len(*received)-before)
	}

	r := assessRisk(riskInput{Threats: report})
	if r.Light != riskRed || !strings.Contains(r.Reasons[0].Simple, "malveillant") {
		t.Errorf("%+v", r.Reasons)
	}
}

func TestThreatErrors(t *testing.T) {
	server, _ := fakeThreatServices(t)
	checker := newTestThreatChecker(server, ThreatIntelConfig{AbuseCHKey: "wrong"})
	report := checker.check(context.Background(), threatSubjects{Hosts: []string{"malware.example"}})
	if len(report.Findings) != 0 || len(report.Errors) != 1 || report.Errors[0] != "URLhaus" {
		t.Errorf("%+v", report)
	}
	if l := report.Lookups; len(l) != 1 || l[0].Service != "URLhaus" || l[0].Failed != 1 || l[0].Subjects[0] != "malware.example" {
		t.Errorf("lookups %+v", l)
	}
	if newThreatChecker(ThreatIntelConfig{}) != nil {
		t.Error("checker without key")
	}
	var none *threatChecker
	if r := none.check(context.Background(), threatSubjects{Hosts: []string{"x.example"}}); len(r.Services) != 0 {
		t.Errorf("%+v", r)
	}
}
