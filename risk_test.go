package main

import (
	"strings"
	"testing"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/filecheck"
)

func TestAssessRisk(t *testing.T) {
	authenticated := &headerAnalysis{FromDomain: "shop.example", Verdicts: []authVerdict{
		{Name: "SPF", Result: "pass", Level: "ok", Source: "serveur de réception mx.example.net"},
		{Name: "DKIM", Result: "pass", Level: "ok", Source: "serveur de réception mx.example.net"},
		{Name: "DMARC", Result: "pass", Level: "ok", Source: "serveur de réception mx.example.net"},
	}}
	spoofed := &headerAnalysis{FromDomain: "bank.example", Verdicts: []authVerdict{
		{Name: "DMARC", Result: "fail", Level: levelDanger, Source: "serveur de réception mx.example.net"},
	}}
	exported := &headerAnalysis{FromDomain: "shop.example", Verdicts: []authVerdict{
		{Name: "DMARC", Result: "fail", Level: levelWarning, Source: "vérification interne"},
	}}
	link := func(level, message string) Link {
		return Link{URL: "https://x.example/", Warnings: []LinkWarning{{level, message}}}
	}

	tests := []struct {
		name  string
		in    riskInput
		light string
		text  string
	}{
		{"clean newsletter", riskInput{Auth: authenticated, Links: []Link{{URL: "https://shop.example/"}}}, riskGreen, "provient bien du domaine"},
		{"spoofed sender", riskInput{Auth: spoofed}, riskRed, "ne vient pas vraiment de bank.example"},
		{"exported mail only", riskInput{Auth: exported}, riskOrange, "Impossible de confirmer"},
		{"deceptive link", riskInput{Auth: authenticated, Links: []Link{link(levelDanger, "Le texte affiché montre paypal.com")}}, riskRed,
			"Un lien est piégé : le texte affiché montre paypal.com"},
		{"two suspect links", riskInput{Auth: authenticated, Links: []Link{link(levelWarning, "Raccourcisseur"), link(levelWarning, "IP")}}, riskOrange, "suspect"},
		{"macro attachment", riskInput{Auth: authenticated, Attachments: []attachmentView{{Report: filecheck.Report{Name: "facture.docm",
			Alerts: []filecheck.Alert{{Level: filecheck.LevelDanger, Message: "macros VBA"}}}}}}, riskRed, "« facture.docm » est dangereuse"},
		{"lookalike", riskInput{Auth: authenticated, Lookalikes: []lookalike{{Domain: "paypa1.com", Brand: "PayPal", Kind: "sosie"}}}, riskRed, "imite PayPal"},
		{"new domain", riskInput{Auth: authenticated, Reputation: reputation{Domains: []domainAge{{Domain: "shop.example", Registered: time.Now().Add(-5 * 24 * time.Hour)}}}},
			riskRed, "créé il y a seulement 5 jours"},
		{"spam verdict", riskInput{Auth: &headerAnalysis{FromDomain: "x.example", Verdicts: authenticated.Verdicts,
			Spam: []spamReport{{Filter: "Gmail", Verdict: "spam", Level: levelWarning, Trusted: true}}}}, riskOrange, "indésirable"},
		{"brand campaign sites of an authenticated brand", riskInput{Auth: &headerAnalysis{FromDomain: "news.migrosmagazine.ch", Verdicts: authenticated.Verdicts},
			Lookalikes: []lookalike{{Domain: "mediasmigros.ch", Brand: "Migros", Kind: "nom", Role: "lien"}, {Domain: "migrosmagazin.ch", Brand: "Migros", Kind: "nom", Role: "lien"}}},
			riskGreen, "provient bien"},
		{"brand names in links count once", riskInput{Auth: authenticated,
			Lookalikes: []lookalike{{Domain: "a-paypal.example", Brand: "PayPal", Kind: "nom", Role: "lien"}, {Domain: "b-paypal.example", Brand: "PayPal", Kind: "nom", Role: "lien"}}},
			riskGreen, "utilise le nom PayPal"},
		{"brand name in the sender", riskInput{Auth: authenticated, Lookalikes: []lookalike{{Domain: "paypal-service.example", Brand: "PayPal", Kind: "nom", Role: "expéditeur (From)"}}},
			riskOrange, "utilise le nom PayPal"},
		{"lookalike link of an authenticated brand", riskInput{Auth: &headerAnalysis{FromDomain: "paypal.com", Verdicts: authenticated.Verdicts},
			Lookalikes: []lookalike{{Domain: "paypa1.com", Brand: "PayPal", Kind: "sosie", Role: "lien"}}}, riskRed, "imite PayPal"},
		{"repeated explanation counted once", riskInput{Auth: &headerAnalysis{FromDomain: "x.example", Verdicts: authenticated.Verdicts,
			Checks: []LinkWarning{{levelWarning, "Reply-To"}, {levelWarning, "Return-Path"}}}}, riskGreen, "pas cohérentes"},
		{"forged spam verdict ignored", riskInput{Auth: &headerAnalysis{FromDomain: "x.example", Verdicts: authenticated.Verdicts,
			Spam: []spamReport{{Filter: "Gmail", Verdict: "suspicion de phishing", Level: levelDanger}}}}, riskGreen, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := assessRisk(tt.in)
			var texts []string
			for _, reason := range r.Reasons {
				texts = append(texts, reason.Simple)
			}
			texts = append(texts, r.Positives...)
			if r.Light != tt.light || !strings.Contains(strings.Join(texts, "\n"), tt.text) {
				t.Errorf("light %s (score %d), want %s; texts:\n%s", r.Light, r.Score, tt.light, strings.Join(texts, "\n"))
			}
			if r.Headline == "" || r.Advice == "" {
				t.Error("headline or advice missing")
			}
		})
	}
	// Trusted domains: links of an authenticated sender are not counted,
	// a sender only internally authenticated is not trusted.
	deceptive := []Link{link(levelDanger, "Le texte affiché montre tdh.org")}
	trusted := &headerAnalysis{FromDomain: "news.tdh.org", Verdicts: authenticated.Verdicts}
	r := assessRisk(riskInput{Auth: trusted, Links: deceptive, TrustedDomains: []string{"tdh.org"},
		Lookalikes: []lookalike{{Domain: "tdh-paypal.example", Brand: "PayPal", Kind: "nom", Role: "lien"}}})
	if !r.Trusted || r.TrustedDomain != "tdh.org" || r.Light != riskGreen || !strings.Contains(strings.Join(r.Positives, " "), "domaines de confiance") {
		t.Errorf("trusted sender: light %s, trusted %v, positives %q", r.Light, r.Trusted, r.Positives)
	}
	r = assessRisk(riskInput{Auth: trusted, Links: deceptive, TrustedDomains: []string{"tdh.org"},
		Attachments: []attachmentView{{Report: filecheck.Report{Name: "x.docm", Alerts: []filecheck.Alert{{Level: filecheck.LevelDanger, Message: "macros"}}}}}})
	if r.Light != riskRed {
		t.Errorf("dangerous attachment from a trusted sender: %s", r.Light)
	}
	exportedTrusted := &headerAnalysis{FromDomain: "tdh.org", Verdicts: exported.Verdicts}
	r = assessRisk(riskInput{Auth: exportedTrusted, Links: deceptive, TrustedDomains: []string{"tdh.org"}})
	if r.Trusted || r.TrustedDomain != "tdh.org" || r.Light != riskRed {
		t.Errorf("unconfirmed trusted sender: light %s, trusted %v", r.Light, r.Trusted)
	}
	if r := assessRisk(riskInput{Auth: trusted, Links: deceptive, TrustedDomains: []string{"other.org", "dh.org"}}); r.Trusted || r.Light != riskRed {
		t.Errorf("other trusted domains: light %s, trusted %v", r.Light, r.Trusted)
	}

	if r := assessRisk(riskInput{Auth: authenticated}); !r.Authenticated || r.Sender != "shop.example" {
		t.Errorf("sender %q authenticated %v", r.Sender, r.Authenticated)
	}
}

func TestLinkSubjects(t *testing.T) {
	links := []Link{
		{URL: "https://www.shop.example/a"},
		{URL: "https://evil.example/login", Warnings: []LinkWarning{{levelDanger, "x"}}},
		{URL: "https://cdn.shop.example/b"},
		{URL: "http://192.0.2.1/x"},
		{URL: "mailto:info@contact.example"},
		{URL: "https://bücher.example/"},
	}
	domains, hosts := linkSubjects(links)
	var d, h []string
	for _, s := range domains {
		d = append(d, s.Value)
	}
	for _, s := range hosts {
		h = append(h, s.Value)
	}
	if strings.Join(d, " ") != "evil.example shop.example contact.example xn--bcher-kva.example" {
		t.Errorf("domains %v", d)
	}
	if strings.Join(h, " ") != "evil.example www.shop.example cdn.shop.example contact.example xn--bcher-kva.example" {
		t.Errorf("hosts %v", h)
	}
}
