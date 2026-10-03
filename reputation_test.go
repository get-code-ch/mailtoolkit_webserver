package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestFindLookalikes(t *testing.T) {
	tests := map[string]string{
		"paypal.com":                "",
		"www.paypal.ch":             "",
		"login.microsoftonline.com": "",
		"paypa1.com":                "sosie PayPal",
		"rnicrosoft.com":            "sosie Microsoft",
		"micorsoft.com":             "sosie Microsoft",
		"postfinace.ch":             "sosie PostFinance",
		"paypal-secure-login.com":   "nom PayPal",
		"paypal.xyz":                "nom PayPal",
		"paypal.com.evil.example":   "nom PayPal",
		"twint-refund.ch":           "nom TWINT",
		"ubs-online.net":            "nom UBS",
		"clubs.ch":                  "",
		"news.migrosmagazine.ch":    "",
		"example.org":               "",
		"booking.com":               "",
	}
	for host, want := range tests {
		found := findLookalikes([]subject{{host, "lien"}})
		got := ""
		if len(found) == 1 {
			got = found[0].Kind + " " + found[0].Brand
		}
		if got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
}

func TestReverseIP(t *testing.T) {
	if got := reverseIP(netip.MustParseAddr("192.0.2.10")); got != "10.2.0.192" {
		t.Errorf("IPv4: %s", got)
	}
	if got := reverseIP(netip.MustParseAddr("2001:db8::1")); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, ".8.b.d.0.1.0.0.2") {
		t.Errorf("IPv6: %s", got)
	}
}

func TestReputationCheck(t *testing.T) {
	resolver := mapResolver{ip: map[string][]string{
		"7.100.51.198.zen.spamhaus.org":    {"127.0.0.4"},
		"7.100.51.198.bl.spamcop.net":      {"127.0.0.2"},
		"evil.example.dbl.spamhaus.org":    {"127.0.1.4"},
		"evil.example.multi.surbl.org":     {"127.0.0.24"},
		"refused.example.dbl.spamhaus.org": {"127.255.255.254"},
		"news.example.multi.surbl.org":     {"127.0.0.1"},
		"mydomain.KEY.dbl.dq.spamhaus.net": {"127.0.1.2"},
		"mtk.example.net.dbl.spamhaus.org": {"127.0.1.2"},
	}}
	checker := newReputationChecker(ReputationConfig{RDAPDisabled: true}, resolver, []string{"mtk.example.net"})
	rep := checker.check(context.Background(),
		[]subject{{"198.51.100.7", "serveur d'envoi"}},
		[]subject{{"evil.example", "lien"}, {"refused.example", "From"}, {"news.example", "lien"}, {"legit.example", "lien"}, {"mtk.example.net", "lien"}})

	var got []string
	for _, l := range rep.Listings {
		got = append(got, fmt.Sprintf("%s %s %s: %s", l.Subject, l.List, l.Level, l.Meaning))
	}
	text := strings.Join(got, "\n")
	for _, want := range []string{
		"198.51.100.7 zen.spamhaus.org danger: machine piratée",
		"198.51.100.7 bl.spamcop.net danger",
		"evil.example dbl.spamhaus.org danger: domaine de phishing",
		"evil.example multi.surbl.org danger: listé par SURBL : logiciels malveillants, phishing",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if len(rep.Listings) != 4 || strings.Contains(text, "mtk.example.net") {
		t.Errorf("listings:\n%s", text)
	}
	if strings.Join(rep.Errors, ",") != "dbl.spamhaus.org,multi.surbl.org" && strings.Join(rep.Errors, ",") != "multi.surbl.org,dbl.spamhaus.org" {
		t.Errorf("errors %v", rep.Errors)
	}

	// Through the Spamhaus Data Query Service, the key is never shown.
	dqs := newReputationChecker(ReputationConfig{RDAPDisabled: true, SpamhausDQSKey: "KEY", DomainLists: []string{"dbl.spamhaus.org"}}, resolver, nil)
	rep = dqs.check(context.Background(), nil, []subject{{"mydomain", "From"}})
	if len(rep.Listings) != 1 || rep.Listings[0].List != "dbl.dq.spamhaus.net" {
		t.Errorf("DQS listings %+v", rep.Listings)
	}

	if (*reputationChecker)(nil).check(context.Background(), nil, nil).Checked != 0 || newReputationChecker(ReputationConfig{Disabled: true}, resolver, nil) != nil {
		t.Error("disabled checker")
	}
}

func TestRDAP(t *testing.T) {
	var queries []string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Path)
		switch r.URL.Path {
		case "/dns.json":
			fmt.Fprintf(w, `{"services":[[["example","test"],["http://insecure.invalid/","%s/registry/"]],[["org"],["http://only-http.invalid/"]]]}`, server.URL)
		case "/registry/domain/new.example":
			fmt.Fprintf(w, `{"events":[{"eventAction":"last changed","eventDate":"2020-01-01T00:00:00Z"},{"eventAction":"registration","eventDate":"%s"}]}`,
				time.Now().Add(-72*time.Hour).UTC().Format(time.RFC3339))
		case "/registry/domain/old.example":
			fmt.Fprint(w, `{"events":[{"eventAction":"registration","eventDate":"2001-05-04T10:00:00Z"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c := newRDAPClient()
	c.client.Transport = server.Client().Transport
	c.bootstrap = server.URL + "/dns.json"

	ctx := context.Background()
	if d, err := c.registration(ctx, "new.example"); err != nil || (domainAge{Registered: d}).Days() != 3 || (domainAge{Registered: d}).Level() != levelDanger {
		t.Errorf("new.example: %v %v", d, err)
	}
	if d, err := c.registration(ctx, "old.example"); err != nil || d.Year() != 2001 || (domainAge{Registered: d}).Level() != "ok" {
		t.Errorf("old.example: %v %v", d, err)
	}
	if _, err := c.registration(ctx, "unknown.example"); err == nil || !strings.Contains(err.Error(), "inconnu") {
		t.Errorf("unknown domain: %v", err)
	}
	if _, err := c.registration(ctx, "plain.org"); err != errNoRDAP {
		t.Errorf("registry without HTTPS: %v", err)
	}
	if _, err := c.registration(ctx, "x.nowhere"); err != errNoRDAP {
		t.Errorf("unknown TLD: %v", err)
	}
	before := len(queries)
	c.registration(ctx, "new.example")
	if len(queries) != before {
		t.Error("RDAP answer not cached")
	}
	if strings.Count(strings.Join(queries, " "), "/dns.json") != 1 {
		t.Error("bootstrap not cached")
	}
}
