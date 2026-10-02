package mailauth

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func spfResolver() *fakeResolver {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":          {"google-site-verification=xyz", "v=spf1 ip4:192.0.2.0/24 include:_spf.provider.test -all"},
			"_spf.provider.test":   {"v=spf1 ip6:2001:db8::/32 a:mail.provider.test/24 mx ~all"},
			"redirect.example":     {"v=spf1 redirect=example.com"},
			"broken-redirect.test": {"v=spf1 redirect=nothing.test"},
			"two.example":          {"v=spf1 -all", "v=spf1 +all"},
			"macro.example":        {"v=spf1 exists:%{ir}.%{v}._spf.%{d} -all"},
			"helo.example":         {"v=spf1 a -all"},
			"unknown.example":      {"v=spf1 foo:bar -all"},
			"voids.example":        {"v=spf1 a:void1.test a:void2.test a:void3.test -all"},
			"temp.example":         {"v=spf1 include:dns-down.test -all"},
			"dns-down.test":        {"v=spf1 -all"},
			"neutral.example":      {"v=spf1 ip4:198.18.0.1"},
		},
		ip: map[string][]string{
			"mail.provider.test":                   {"198.51.100.5"},
			"mx1.provider.test":                    {"203.0.113.9", "2001:db8:ffff::9"},
			"7.2.0.192.in-addr._spf.macro.example": {"127.0.0.2"},
			"helo.example":                         {"192.0.2.99"},
		},
		mx:   map[string][]string{"_spf.provider.test": {"mx1.provider.test"}},
		temp: map[string]bool{"dns-down.test": true},
	}
	// A chain of 11 includes exceeds the 10 DNS lookups limit.
	for i := range 11 {
		r.txt[fmt.Sprintf("chain%d.test", i)] = []string{fmt.Sprintf("v=spf1 include:chain%d.test -all", i+1)}
	}
	r.txt["chain11.test"] = []string{"v=spf1 +all"}
	return r
}

func TestCheckSPF(t *testing.T) {
	resolver := spfResolver()
	tests := []struct {
		ip, sender, helo string
		want, mechanism  string
	}{
		{"192.0.2.7", "joe@example.com", "mx.example.com", ResultPass, "ip4:192.0.2.0/24"},
		{"198.51.100.200", "joe@example.com", "", ResultPass, "include:_spf.provider.test"}, // a:/24
		{"203.0.113.9", "joe@example.com", "", ResultPass, "include:_spf.provider.test"},    // mx
		{"2001:db8::1", "joe@example.com", "", ResultPass, "include:_spf.provider.test"},    // ip6
		{"203.0.113.200", "joe@example.com", "", ResultFail, "-all"},
		{"::ffff:192.0.2.8", "<joe@example.com>", "", ResultPass, "ip4:192.0.2.0/24"},
		{"192.0.2.7", "anyone@redirect.example", "", ResultPass, "redirect=example.com"},
		{"203.0.113.200", "anyone@redirect.example", "", ResultFail, "redirect=example.com"},
		{"192.0.2.7", "x@broken-redirect.test", "", ResultPermError, ""},
		{"192.0.2.7", "x@two.example", "", ResultPermError, ""},
		{"192.0.2.7", "x@nothing.test", "", ResultNone, ""},
		{"192.0.2.7", "x@macro.example", "", ResultPass, "exists:%{ir}.%{v}._spf.%{d}"},
		{"192.0.2.8", "x@macro.example", "", ResultFail, "-all"},
		{"192.0.2.99", "", "helo.example", ResultPass, "a"},
		{"192.0.2.7", "x@unknown.example", "", ResultPermError, ""},
		{"192.0.2.7", "x@voids.example", "", ResultPermError, ""},
		{"192.0.2.7", "x@temp.example", "", ResultTempError, ""},
		{"192.0.2.7", "x@chain0.test", "", ResultPermError, ""},
		{"192.0.2.7", "x@neutral.example", "", ResultNeutral, ""},
	}
	for _, tt := range tests {
		t.Run(tt.sender+"/"+tt.ip, func(t *testing.T) {
			got := CheckSPF(context.Background(), resolver, netip.MustParseAddr(tt.ip), tt.sender, tt.helo)
			if got.Result != tt.want || got.Mechanism != tt.mechanism {
				t.Errorf("CheckSPF = %s (%q, %s), want %s (%q)", got.Result, got.Mechanism, got.Reason, tt.want, tt.mechanism)
			}
		})
	}
}

func TestCheckSPFDetails(t *testing.T) {
	got := CheckSPF(context.Background(), spfResolver(), netip.MustParseAddr("192.0.2.7"), "Joe@Example.com", "")
	if got.Domain != "example.com" || !strings.HasPrefix(got.Record, "v=spf1 ip4:") || got.IP.String() != "192.0.2.7" {
		t.Errorf("result = %+v", got)
	}
	if got := CheckSPF(context.Background(), spfResolver(), netip.Addr{}, "joe@example.com", ""); got.Result != ResultNone {
		t.Errorf("without IP: %+v", got)
	}
}

func TestMacroExpansion(t *testing.T) {
	c := &spfChecker{sender: "strong-bad@email.example.com", ip: netip.MustParseAddr("192.0.2.3"), helo: "mx.example.org"}
	// Examples of RFC 7208 §7.4
	for spec, want := range map[string]string{
		"%{s}":                              "strong-bad@email.example.com",
		"%{o}":                              "email.example.com",
		"%{d}":                              "email.example.com",
		"%{d4}":                             "email.example.com",
		"%{d3}":                             "email.example.com",
		"%{d2}":                             "example.com",
		"%{d1}":                             "com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l}":                              "strong-bad",
		"%{l-}":                             "strong.bad",
		"%{lr}":                             "strong-bad",
		"%{lr-}":                            "bad.strong",
		"%{l1r-}":                           "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
	} {
		got, err := c.expand(spec, "email.example.com")
		if err != nil || got != want {
			t.Errorf("expand(%q) = %q, %v; want %q", spec, got, err, want)
		}
	}
	c.ip = netip.MustParseAddr("2001:db8::cb01")
	got, _ := c.expand("%{ir}.%{v}._spf.%{d2}", "email.example.com")
	want := "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
	if got != want {
		t.Errorf("IPv6 expansion = %q, want %q", got, want)
	}
}
