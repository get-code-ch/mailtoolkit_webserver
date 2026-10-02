package mailauth

import (
	"context"
	"testing"
)

func TestOrgDomain(t *testing.T) {
	for domain, want := range map[string]string{
		"mail.bank.co.uk": "bank.co.uk",
		"bank.co.uk":      "bank.co.uk",
		"a.b.example.com": "example.com",
		"Example.COM.":    "example.com",
		"user.github.io":  "user.github.io",
		"news.migros.ch":  "migros.ch",
	} {
		if got := OrgDomain(domain); got != want {
			t.Errorf("OrgDomain(%q) = %q, want %q", domain, got, want)
		}
	}
}

func TestCheckDMARC(t *testing.T) {
	resolver := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com":  {"v=DMARC1; p=reject; sp=quarantine; adkim=s; pct=50; rua=mailto:d@example.com"},
			"_dmarc.relaxed.test": {"v=DMARC1; p=quarantine"},
			"_dmarc.double.test":  {"v=DMARC1; p=reject", "v=DMARC1; p=none"},
			"_dmarc.bad.test":     {"p=reject; v=DMARC1"},
		},
		temp: map[string]bool{"_dmarc.down.test": true},
	}
	pass := func(domain string) SPFResult { return SPFResult{Result: ResultPass, Domain: domain} }
	signed := func(domain string) []DKIMResult { return []DKIMResult{{Result: ResultPass, Domain: domain}} }
	tests := []struct {
		name       string
		from       string
		spf        SPFResult
		dkim       []DKIMResult
		want       string
		policy     string
		spfAligned bool
		dkimAlign  bool
	}{
		{"spf relaxed alignment", "example.com", pass("bounce.example.com"), nil, ResultPass, "reject", true, false},
		{"dkim strict alignment", "example.com", SPFResult{Result: ResultFail}, signed("example.com"), ResultPass, "reject", false, true},
		{"dkim subdomain not aligned in strict mode", "example.com", SPFResult{Result: ResultFail}, signed("mail.example.com"), ResultFail, "reject", false, false},
		{"third party signature", "example.com", pass("esp.example.net"), signed("esp.example.net"), ResultFail, "reject", false, false},
		{"failed signature ignored", "example.com", SPFResult{}, []DKIMResult{{Result: ResultFail, Domain: "example.com"}}, ResultFail, "reject", false, false},
		{"subdomain uses sp", "news.example.com", SPFResult{}, nil, ResultFail, "quarantine", false, false},
		{"relaxed dkim subdomain", "relaxed.test", SPFResult{}, signed("mail.relaxed.test"), ResultPass, "quarantine", false, true},
		{"no record", "nodmarc.test", pass("nodmarc.test"), nil, ResultNone, "", false, false},
		{"several records", "double.test", pass("double.test"), nil, ResultNone, "", false, false},
		{"v not first", "bad.test", pass("bad.test"), nil, ResultNone, "", false, false},
		{"dns failure", "down.test", pass("down.test"), nil, ResultTempError, "", false, false},
		{"no from", "", pass("x.test"), nil, ResultPermError, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckDMARC(context.Background(), resolver, tt.from, tt.spf, tt.dkim)
			if got.Result != tt.want || got.Policy != tt.policy || got.SPFAligned != tt.spfAligned || got.DKIMAligned != tt.dkimAlign {
				t.Errorf("CheckDMARC = %+v", got)
			}
		})
	}
	if got := CheckDMARC(context.Background(), resolver, "example.com", pass("example.com"), nil); got.Pct != 50 {
		t.Errorf("pct = %d", got.Pct)
	}
}
