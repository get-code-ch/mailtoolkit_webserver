package main

import (
	"strings"
	"testing"

	"github.com/get-code-ch/mailtoolkit"
)

// htmlMail builds a mail with an HTML part and a plain text part.
func htmlMail(t *testing.T, htmlBody, textBody string) mailtoolkit.Mail {
	t.Helper()
	raw := "From: a@example.org\r\nSubject: links\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + textBody + "\r\n" +
		"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + htmlBody + "\r\n--b--\r\n"
	mail, err := mailtoolkit.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return mail
}

func findLink(t *testing.T, links []Link, url string) Link {
	t.Helper()
	for _, l := range links {
		if l.URL == url {
			return l
		}
	}
	var urls []string
	for _, l := range links {
		urls = append(urls, l.URL)
	}
	t.Fatalf("link %q not found in %q", url, urls)
	return Link{}
}

func hasWarning(l Link, level, contains string) bool {
	for _, w := range l.Warnings {
		if w.Level == level && strings.Contains(w.Message, contains) {
			return true
		}
	}
	return false
}

func TestExtractLinksPhishingPatterns(t *testing.T) {
	body := `<html><head>
<meta http-equiv="refresh" content="0; URL='https://refresh.example/'">
<style>.x { background: url("https://css.example/bg.png") }</style>
<base href="https://base.example/">
</head><body>
<a href="https://paypal.com.evil.example/login">https://www.paypal.com</a>
<a href="https://www.bank.example/account">bank.example</a>
<a href="java&#9;script:alert(1)">Cliquez ici</a>
<a href="https://paypal.com@evil.example/">PayPal</a>
<a href="http://192.0.2.10:8080/x">serveur</a>
<a href="https://bit.ly/abc">offre</a>
<a href="https://xn--pypal-4ve.com/">paypal.com</a>
<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftarget.example%2Fpage&amp;data=1">lien</a>
<a href="https://news.example/"><img src="https://news.example/logo.png" alt="Logo"></a>
<form action="https://collect.example/post"><input name="password"></form>
<img src="https://track.example/p.gif" width="1" height="1">
<img src="cid:image001@x">
<div style="background-image:url(https://inline.example/bg.jpg)">x</div>
<a href="#top">haut</a>
<a href="https://www.bank.example/account">bank.example</a>
</body></html>`
	links := extractLinks(htmlMail(t, body, "Voir www.text.example/offre. Ou https://plain.example/a?b=1,"))

	cases := []struct {
		url, level, warning string
	}{
		{"https://paypal.com.evil.example/login", levelDanger, "paypal.com, mais le lien pointe vers paypal.com.evil.example"},
		{"javascript:alert(1)", levelDanger, "javascript:"},
		{"https://paypal.com@evil.example/", levelDanger, "la vraie destination est evil.example"},
		{"http://192.0.2.10:8080/x", levelWarning, "Adresse IP"},
		{"http://192.0.2.10:8080/x", levelWarning, "Port inhabituel : 8080"},
		{"http://192.0.2.10:8080/x", levelInfo, "non chiffrée"},
		{"https://bit.ly/abc", levelWarning, "raccourci"},
		{"https://xn--pypal-4ve.com/", levelWarning, "internationalisé"},
		{"https://xn--pypal-4ve.com/", levelDanger, "le lien pointe vers"},
		{"https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftarget.example%2Fpage&data=1", levelInfo, "Redirige vers target.example"},
		{"https://collect.example/post", levelDanger, "Formulaire"},
		{"https://track.example/p.gif", levelInfo, "pixel de suivi"},
		{"https://refresh.example/", levelDanger, "Redirection automatique"},
		{"https://base.example/", levelWarning, "<base>"},
	}
	for _, c := range cases {
		if l := findLink(t, links, c.url); !hasWarning(l, c.level, c.warning) {
			t.Errorf("%s: missing %s warning %q, got %+v", c.url, c.level, c.warning, l.Warnings)
		}
	}

	bank := findLink(t, links, "https://www.bank.example/account")
	if bank.Level() != "" || bank.Count != 2 || bank.Text != "bank.example" {
		t.Errorf("legitimate link = %+v", bank)
	}
	if l := findLink(t, links, "https://xn--pypal-4ve.com/"); l.Host != "pаypal.com" {
		t.Errorf("punycode host displayed as %q", l.Host)
	}
	if l := findLink(t, links, "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftarget.example%2Fpage&data=1"); l.Target != "https://target.example/page" {
		t.Errorf("redirect target = %q", l.Target)
	}
	if l := findLink(t, links, "https://news.example/"); l.Text != "[image : Logo]" {
		t.Errorf("image link text = %q", l.Text)
	}
	findLink(t, links, "https://news.example/logo.png")
	findLink(t, links, "https://css.example/bg.png")
	findLink(t, links, "https://inline.example/bg.jpg")
	if l := findLink(t, links, "http://www.text.example/offre"); l.Part != "text/plain" {
		t.Errorf("text link part = %q", l.Part)
	}
	findLink(t, links, "https://plain.example/a?b=1")

	for _, l := range links {
		if strings.HasPrefix(l.URL, "cid:") || strings.HasPrefix(l.URL, "#") {
			t.Errorf("internal reference listed: %s", l.URL)
		}
	}
}

func TestExtractLinksCharset(t *testing.T) {
	raw := "Content-Type: text/html; charset=windows-1252\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"<a href=3D\"https://shop.example/\">Payez 10 =80 ici =E9</a>\r\n"
	mail, err := mailtoolkit.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	links := extractLinks(mail)
	if len(links) != 1 || links[0].Text != "Payez 10 € ici é" {
		t.Errorf("links = %+v", links)
	}
}

func TestExtractLinksRealMail(t *testing.T) {
	mail, err := mailtoolkit.Parse(readTestdata(t, "multipart.eml"))
	if err != nil {
		t.Fatal(err)
	}
	links := extractLinks(mail)
	if len(links) < 10 {
		t.Errorf("only %d links found in the newsletter", len(links))
	}
	for _, l := range links {
		if l.Level() == levelDanger {
			t.Errorf("newsletter link flagged as dangerous: %+v", l)
		}
	}
}

func TestDisplayedHost(t *testing.T) {
	for text, want := range map[string]string{
		"https://www.PayPal.com/login": "paypal.com",
		"paypal.com":                   "paypal.com",
		"Cliquez ici":                  "",
		"support@paypal.com":           "",
		"Mon compte PayPal.com":        "",
		"café.example":                 "xn--caf-dma.example",
	} {
		if got := displayedHost(text); got != want {
			t.Errorf("displayedHost(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestGroupLinks(t *testing.T) {
	links := []Link{
		{URL: "https://www.shop.example/b", Host: "www.shop.example"},
		{URL: "https://evil.example/login", Host: "evil.example", Warnings: []LinkWarning{{levelDanger, "x"}}},
		{URL: "relative/path"},
		{URL: "https://mail.shop.example/a", Host: "mail.shop.example", Warnings: []LinkWarning{{levelInfo, "http"}}},
		{URL: "mailto:info@shop.example", Host: "info@shop.example"},
		{URL: "http://192.0.2.1/x", Host: "192.0.2.1", Warnings: []LinkWarning{{levelWarning, "ip"}}},
		{URL: "https://news.bank.co.uk/", Host: "news.bank.co.uk"},
	}
	groups := groupLinks(links)
	var got []string
	for _, g := range groups {
		var urls []string
		for _, l := range g.Links {
			urls = append(urls, l.URL)
		}
		got = append(got, g.Domain+"["+g.Level+"]="+strings.Join(urls, ","))
	}
	want := []string{
		"192.0.2.1[warning]=http://192.0.2.1/x",
		"bank.co.uk[]=https://news.bank.co.uk/",
		"evil.example[danger]=https://evil.example/login",
		"shop.example[info]=https://mail.shop.example/a,https://www.shop.example/b,mailto:info@shop.example",
		"[]=relative/path",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("groups:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !groups[0].Open() || !groups[2].Open() || groups[3].Open() {
		t.Error("only suspect groups should be open")
	}
}

func TestClickTrackers(t *testing.T) {
	dynamics := "https://7cb5723be1894fa9ac5ab12e8bd664b8.105.eu.prod.marketingusercontent.com/api/orgs/7cb5723b-e189-4fa9-ac5a-b12e8bd664b8/r/d8jaLotkQUaRbEl7PewAAA4AAAA" +
		"?msdynmkt_target=%7B%22TargetUrl%22%3A%22https%253A%252F%252Ftdh.org%252F%22%2C%22RedirectOptions%22%3A%7B%226%22%3A%22mktprf%22%7D%7D&msdynmkt_digest=jWv"
	tests := []struct {
		url, text, level, warning, target string
	}{
		{dynamics, "tdh.org", levelInfo, "Lien de suivi des clics (Microsoft Dynamics 365 Customer Insights)", "https://tdh.org/"},
		{"https://abc.list-manage.com/track/click?u=1&id=2&e=3", "shop.example", levelWarning, "sans indiquer sa destination finale", ""},
		{"https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypal.com.evil.example%2F&data=1", "paypal.com", levelDanger, "mais le lien pointe vers", "https://paypal.com.evil.example/"},
		{"https://evil.example/go?url=https%3A%2F%2Fpaypal.com%2F", "paypal.com", levelDanger, "un service inconnu qui annonce rediriger vers paypal.com", "https://paypal.com/"},
		{"https://urldefense.com/v3/__https://bank.example/login__;!!abc$", "bank.example", levelInfo, "Proofpoint URL Defense", "https://bank.example/login"},
		{"https://links.iterable.com/u/click?_t=x&_m=y", "", levelInfo, "Lien de suivi des clics (Iterable)", ""},
	}
	for _, tt := range tests {
		l := analyzeLink(tt.url, tt.text, "lien", "text/html")
		if l.Level() != tt.level || !hasWarning(l, tt.level, tt.warning) || l.Target != tt.target {
			t.Errorf("%s (%q): level %q, target %q, warnings %+v", tt.url, tt.text, l.Level(), l.Target, l.Warnings)
		}
	}
	if trackerOf("marketingusercontent.com.evil.example") != "" || trackerOf("x.105.eu.prod.marketingusercontent.com") == "" {
		t.Error("trackerOf suffix matching")
	}
}
