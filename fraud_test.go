package main

import (
	"strings"
	"testing"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/filecheck"
	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
	"github.com/get-code-ch/mailtoolkit_webserver/qrscan"
)

func TestIBAN(t *testing.T) {
	for _, iban := range []string{"CH9300762011623852957", "DE89370400440532013000", "FR1420041010050500013M02606", "GB29NWBK60161331926819"} {
		if !validIBAN(iban) {
			t.Errorf("%s refused", iban)
		}
	}
	for _, iban := range []string{"CH9300762011623852958", "DE8937040044053201300", "XX00", "CH93-0076"} {
		if validIBAN(iban) {
			t.Errorf("%s accepted", iban)
		}
	}
	text := "Merci de verser le montant sur CH93 0076 2011 6238 5295 7 Merci. Ancien : DE89370400440532013000, faux : CH93 0076 2011 6238 5295 8."
	if got := findIBANs(text); strings.Join(got, ",") != "CH9300762011623852957,DE89370400440532013000" {
		t.Errorf("%v", got)
	}
}

func qrBill(iban, country, refType string) string {
	lines := []string{"SPC", "0200", "1", iban, "S", "Robert Schneider AG", "Rue du Lac", "1268", "2501", "Biel", country,
		"", "", "", "", "", "", "", "1949.75", "CHF", "S", "Pia-Maria Rutschmann-Schnyder", "Grosse Marktgasse", "28", "9400",
		"Rorschach", "CH", refType, "210000000003139471430009017", "Auftrag vom 15.06.2020", "EPD"}
	return strings.Join(lines, "\r\n")
}

func TestPayments(t *testing.T) {
	p, ok := parsePayment(qrBill("CH4431999123000889012", "CH", "QRR"))
	if !ok || !p.Valid || p.Creditor != "Robert Schneider AG" || p.Amount != "1949.75" || p.Currency != "CHF" || len(p.Problems) != 0 {
		t.Errorf("%+v", p)
	}
	if p.FormattedIBAN() != "CH44 3199 9123 0008 8901 2" {
		t.Error(p.FormattedIBAN())
	}
	p, _ = parsePayment(qrBill("CH4431999123000889012", "CH", "NON"))
	if len(p.Problems) != 1 || !strings.Contains(p.Problems[0], "QR-IBAN") {
		t.Errorf("%+v", p.Problems)
	}
	p, _ = parsePayment(qrBill("DE89370400440532013000", "DE", "NON"))
	if len(p.Problems) != 2 || p.Level() != levelWarning {
		t.Errorf("%+v", p.Problems)
	}
	p, _ = parsePayment(qrBill("CH4431999123000889013", "CH", "QRR"))
	if p.Valid || !strings.Contains(p.Problems[0], "IBAN invalide") {
		t.Errorf("%+v", p)
	}
	p, ok = parsePayment("BCD\n002\n1\nSCT\nBPOTBEB1\nRed Cross of Belgium\nBE72000000001616\nEUR1.00\nCHAR\n\nUrgency fund")
	if !ok || !p.Valid || p.Currency != "EUR" || p.Amount != "1.00" || p.Creditor != "Red Cross of Belgium" || p.Message != "Urgency fund" {
		t.Errorf("%+v", p)
	}
	if _, ok := parsePayment("hello"); ok {
		t.Error("text taken for a payment")
	}
}

func TestClassifyQR(t *testing.T) {
	q := classifyQR(qrscan.Code{Text: "https://xn--pypal-4ve.com/login", Source: "image"})
	if q.Kind != "lien" || q.Link == nil || q.Link.Source != "QR code" || q.Level() != levelWarning {
		t.Errorf("%+v", q)
	}
	for text, kind := range map[string]string{"WIFI:S:guest;T:WPA;P:secret;;": "Wi-Fi", "BEGIN:VCARD\nFN:A\nEND:VCARD": "contact",
		qrBill("CH4431999123000889012", "CH", "QRR"): "paiement", "Ticket 42": "texte", "www.example.com": "lien"} {
		if q := classifyQR(qrscan.Code{Text: text}); q.Kind != kind {
			t.Errorf("%q: %s", text, q.Kind)
		}
	}
}

func TestAnalyzeText(t *testing.T) {
	f := analyzeText("Changement de coordonnées bancaires", "Bonjour, veuillez noter nos nouvelles coordonnées bancaires pour le "+
		"paiement de la facture : CH93 0076 2011 6238 5295 7. C’est urgent.")
	if !f.has(cueBankChange) || !f.has(cuePayment) || !f.has(cueUrgency) || len(f.IBANs) != 1 {
		t.Errorf("%+v", f)
	}
	f = analyzeText("Kurze Frage", "Sind Sie verfügbar? Ich brauche Ihre Hilfe für eine dringende und streng vertrauliche Überweisung.")
	if !f.has(cueAvailability) || !f.has(cueSecrecy) || !f.has(cuePayment) || !f.has(cueUrgency) {
		t.Errorf("%+v", f.Cues)
	}
	// Words are matched whole: "mfa" is not found in "mfahrer", "today" is no cue.
	f = analyzeText("Newsletter", "Notre mfahrer est là today avec des réductions")
	if len(f.Cues) != 0 {
		t.Errorf("%+v", f.Cues)
	}
	if got := htmlText([]byte(`<html><head><title>T</title><style>p{color:red}</style></head><body><p>Bonjour</p><p>Mot de&nbsp;passe</p><script>x()</script></body></html>`)); strings.Contains(got, "color") || strings.Contains(got, "x()") || !strings.Contains(got, "Mot de passe") {
		t.Errorf("%q", got)
	}
	if !analyzeText("", htmlText([]byte("<p>Mot de&nbsp;passe expiré</p>"))).has(cueCredentials) {
		t.Error("non-breaking space not normalized")
	}
}

func authenticated(domain, name string) *headerAnalysis {
	return &headerAnalysis{FromDomain: domain, FromAddress: "jean.dupont@" + domain, FromName: name,
		Verdicts: []authVerdict{{Name: "DMARC", Result: mailauth.ResultPass, Source: "mx.example.org"}}}
}

func TestFraudRisk(t *testing.T) {
	tests := []struct {
		name    string
		auth    *headerAnalysis
		subject string
		text    string
		codes   []qrCode
		light   string
		reason  string
	}{
		{"bank details change", authenticated("supplier.example", ""), "Facture", "Suite à un changement de banque, merci d'effectuer le virement sur notre nouveau compte.",
			nil, riskRed, "changement de coordonnées bancaires"},
		{"CEO fraud", authenticated("gmail.com", "Jean Dupont"), "Confidentiel", "Es-tu disponible ? J'ai besoin que tu fasses un virement, strictement confidentiel.",
			nil, riskRed, "fraude au président"},
		{"gift cards", authenticated("example.org", ""), "Urgent", "Achète 5 cartes cadeaux Google Play immédiatement et envoie-moi les codes.",
			nil, riskRed, "cartes cadeaux"},
		{"urgent invoice from a company", authenticated("supplier.example", ""), "Rappel", "Votre facture est échue, merci de procéder au paiement au plus vite.",
			nil, riskGreen, "paiement urgent"},
		{"urgent invoice from a freemail", authenticated("gmail.com", ""), "Rappel", "Votre facture est échue, merci de procéder au paiement au plus vite.",
			nil, riskOrange, "messagerie gratuite"},
		{"credentials under pressure", authenticated("example.org", ""), "Action requise", "Votre compte sera suspendu : confirmez votre mot de passe dans les 24 heures.",
			nil, riskOrange, "identifiants"},
		{"opener", authenticated("gmail.com", ""), "", "Are you available? I need a quick favor.", nil, riskGreen, "premier message"},
		{"newsletter", authenticated("shop.example", ""), "Soldes", "Profitez de nos offres sur les cartes cadeaux, livraison gratuite.", nil, riskGreen, ""},
		{"quishing", authenticated("example.org", ""), "MFA", "Votre double authentification expire. Scannez le code QR avec votre téléphone.",
			[]qrCode{classifyQR(qrscan.Code{Text: "https://mfa-renew.example.net/x", Source: "image001.png"})}, riskRed, "quishing"},
		{"QR code to a site", authenticated("example.org", ""), "Événement", "Votre billet pour le concert.",
			[]qrCode{classifyQR(qrscan.Code{Text: "https://tickets.example.org/42", Source: "billet.pdf"})}, riskGreen, "QR code qui mène vers tickets.example.org"},
		{"doubtful QR-bill", authenticated("example.org", ""), "Facture", "Veuillez trouver la facture.",
			[]qrCode{classifyQR(qrscan.Code{Text: qrBill("DE89370400440532013000", "DE", "NON"), Source: "facture.pdf"})}, riskOrange, "ordre de paiement"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := assessRisk(riskInput{Auth: tt.auth, Fraud: analyzeText(tt.subject, tt.text), QRCodes: tt.codes})
			if r.Light != tt.light {
				t.Errorf("light %s (score %d), want %s: %+v", r.Light, r.Score, tt.light, r.Reasons)
			}
			found := tt.reason == ""
			for _, reason := range r.Reasons {
				found = found || strings.Contains(reason.Simple, tt.reason)
			}
			if !found {
				t.Errorf("no reason with %q: %+v", tt.reason, r.Reasons)
			}
		})
	}
}

func TestImpersonation(t *testing.T) {
	trusted, protected := []string{"kite-project.net"}, []string{"Jean Dupont"}
	tests := []struct {
		auth   *headerAnalysis
		weight int
		reason string
	}{
		{authenticated("gmail.com", "Dupont, Jean"), 3, "usurpation"},
		{authenticated("kite-project.net", "Jean Dupont"), 0, ""},
		{&headerAnalysis{FromDomain: "kite-project.net", FromAddress: "jean@kite-project.net", FromName: "Jean Dupont"}, 2, "n'a pas confirmé"},
		{authenticated("mail.example", "Kite Project Support"), 2, "nom de votre organisation"},
		{authenticated("mail.example", "Jeanne Dupontel"), 0, ""},
	}
	for _, tt := range tests {
		var r riskReport
		total, text := 0, ""
		assessImpersonation(&r, tt.auth, trusted, protected, func(level string, weight int, anchor, simple, detail string) {
			total += weight
			text += simple
		})
		if total != tt.weight || !strings.Contains(text, tt.reason) {
			t.Errorf("%s: weight %d, %q", tt.auth.FromName, total, text)
		}
	}
}

func TestOwnLookalikes(t *testing.T) {
	trusted := []string{"kite-project.net"}
	found := findLookalikes([]subject{{"kite-project-helpdesk.net", "expéditeur"}, {"kite-project.mfa-renew.top", "lien"},
		{"kiteproiect.net", "lien"}, {"mail.kite-project.net", "expéditeur"}, {"example.com", "lien"}}, trusted)
	if len(found) != 3 || !found[0].Own || found[0].Kind != "nom" || found[1].Kind != "nom" || found[2].Kind != "sosie" {
		t.Fatalf("%+v", found)
	}
	r := assessRisk(riskInput{Auth: authenticated("kite-project-helpdesk.net", ""), Lookalikes: found, TrustedDomains: trusted})
	if r.Light != riskRed || r.Score != 3+2+4 {
		t.Errorf("%s %d %+v", r.Light, r.Score, r.Reasons)
	}
	if len(findLookalikes([]subject{{"kite-project-helpdesk.net", "expéditeur"}}, nil)) != 0 {
		t.Error("found without trusted domains")
	}
}

func TestHostingLinks(t *testing.T) {
	tests := map[string]string{
		"https://v912zlhw-vz5u0n2-zqdrr2y7uv.besaduromnvcx.workers.dev/f": levelWarning,
		"https://login-portal.pages.dev/":                                 levelWarning,
		"https://contoso.sharepoint.com/:b:/s/x":                          levelInfo,
		"https://newsletter2026.example.com/":                             "",
		"https://www.example.com/":                                        "",
	}
	for raw, want := range tests {
		if got := analyzeLink(raw, "", "lien", "text/html").Level(); got != want {
			t.Errorf("%s: %q", raw, got)
		}
	}
	// Images come from CDNs with generated names.
	if l := analyzeLink("https://d1a2b3c4d5e6f7.cloudfront.net/logo.png", "", "image", "text/html"); l.Level() != "" {
		t.Errorf("%+v", l.Warnings)
	}
}

func TestDisplayBrand(t *testing.T) {
	tests := []struct {
		name, domain string
		weight       int
	}{
		{"DHL EXPRESS", "sic-net.co.jp", 3},
		{"Microsoft 365 Security", "secure-alerts.example", 3},
		{"SharePoint Online", "docs-share.example", 3},
		{"Swiss Post PostFinance", "pf-secure.example", 3},
		{"DHL Express", "dhl.com", 0},
		{"Microsoft Teams", "mail.microsoft", 0},
		{"Booking confirmation", "hotel.example", 0},
		{"Ricardo Silva", "example.org", 0},
		{"Jean Dupont", "example.org", 0},
	}
	for _, tt := range tests {
		total := 0
		assessDisplayBrand(authenticated(tt.domain, tt.name), func(level string, weight int, anchor, simple, detail string) { total += weight })
		if total != tt.weight {
			t.Errorf("%s <%s>: %d", tt.name, tt.domain, total)
		}
	}
}

func TestImageOnly(t *testing.T) {
	parse := func(body string) mailtoolkit.Mail {
		m, err := mailtoolkit.Parse([]byte("From: a@example.org\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + body))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	banner := `<div>CAUTION: This email originated from outside of the organization. Do not click links.</div>`
	if !imageOnly(parse(banner + `<img src="cid:a" width="576">`)) {
		t.Error("image only mail not recognized")
	}
	if imageOnly(parse(`<p>Bonjour, voici les nouvelles de la semaine et notre sélection.</p><img src="cid:a">`)) {
		t.Error("mail with text taken for an image")
	}
	if imageOnly(parse(`<p>Ok</p><img src="https://t.example/p.gif" width="1" height="1">`)) {
		t.Error("tracking pixel counted")
	}
}

func TestLureRisk(t *testing.T) {
	lure := func(link string) attachmentView {
		return attachmentView{Report: filecheck.Report{Name: "Offre.pdf", Lure: true, Links: []string{link},
			Alerts: []filecheck.Alert{{Level: filecheck.LevelWarning, Message: filecheck.MessageLure + " : …"}}}}
	}
	for link, light := range map[string]string{
		"https://contoso-my.sharepoint.com/:b:/g/personal/x": riskRed,
		"https://x1y2z3a4b5c6d7.workers.dev/":                riskRed,
		"https://www.example.org/conditions":                 riskOrange,
	} {
		r := assessRisk(riskInput{Auth: authenticated("partner.example", ""), Attachments: []attachmentView{lure(link)}})
		if r.Light != light {
			t.Errorf("%s: %s %+v", link, r.Light, r.Reasons)
		}
	}
}
