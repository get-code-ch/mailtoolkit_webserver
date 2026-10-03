package main

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// headerAnalysis is the analysis of the headers of an extracted mail.
type headerAnalysis struct {
	Hops []hopView
	// Source is the hop detected as the reception from the sender's server,
	// Selected the hop whose IP is used for SPF (-1 when none).
	Source   int
	Selected int
	MailFrom string
	SPF      mailauth.SPFResult
	DKIM     []mailauth.DKIMResult
	DMARC    mailauth.DMARCResult
	ARC      mailauth.ARCResult
	Provider []providerView
	// Verdicts combine, for SPF, DKIM and DMARC, the result written by the
	// receiving provider and the internal verification.
	Verdicts []authVerdict
	Checks   []LinkWarning
	Fields   []mailauth.Field
	Groups   []headerGroup
	// Spam are the verdicts of the antispam filters.
	Spam []spamReport
	// FromDomain is the domain of the displayed sender, Senders the
	// domains naming the sender (From, Reply-To, Return-Path, DKIM d=).
	FromDomain  string
	FromAddress string
	Senders     []subject
	// Relay is the authenticated service that sent the mail on behalf of
	// one of its users, nil if none.
	Relay *relayService
	// Part is the content part shown with the analysis, kept in the links
	// choosing another hop.
	Part string
	// Converted is set for a mail converted from Outlook .msg: its body is
	// rebuilt, so its DKIM signatures cannot verify.
	Converted bool
}

type hopView struct {
	mailauth.Hop
	Index  int
	Public bool
}

// DateText and DelayText format a hop for the template.
func (h hopView) DateText() string {
	if h.Date.IsZero() {
		return ""
	}
	return h.Date.Local().Format("02.01.2006 15:04:05")
}

func (h hopView) DelayText() string {
	switch {
	case h.Delay == 0:
		return ""
	case h.Delay < 0:
		return "−" + (-h.Delay).String()
	}
	return "+" + h.Delay.String()
}

// analyzeHeaders checks the authentication of a raw mail. hop selects the
// Received hop whose IP is used for SPF, -1 for the detected one.
func analyzeHeaders(ctx context.Context, resolver mailauth.Resolver, raw []byte, hop int) headerAnalysis {
	m := mailauth.ParseMessage(raw)
	hops := mailauth.Hops(m)
	a := headerAnalysis{
		Source:   mailauth.SourceHop(hops),
		Fields:   m.Fields,
		MailFrom: strings.Trim(m.Get("Return-Path"), "<> "),
	}
	for i, h := range hops {
		a.Hops = append(a.Hops, hopView{Hop: h, Index: i, Public: isPublicHop(h)})
	}
	a.Selected = a.Source
	if hop >= 0 && hop < len(hops) && hops[hop].IP.IsValid() {
		a.Selected = hop
	}

	if a.Selected >= 0 {
		source := hops[a.Selected]
		a.SPF = mailauth.CheckSPF(ctx, resolver, source.IP, a.MailFrom, source.From)
	} else {
		a.SPF = mailauth.SPFResult{Result: mailauth.ResultNone, Reason: "aucune adresse IP d'expéditeur dans les en-têtes Received"}
	}
	a.DKIM = mailauth.VerifyDKIM(ctx, resolver, m)
	a.ARC = mailauth.VerifyARC(ctx, resolver, m)

	fromDomain := ""
	if from, err := (&mail.AddressParser{WordDecoder: wordDecoder}).ParseList(m.Get("From")); err == nil && len(from) == 1 {
		fromDomain = domainOfAddress(from[0].Address)
		a.FromAddress = from[0].Address
	}
	a.DMARC = mailauth.CheckDMARC(ctx, resolver, fromDomain, a.SPF, a.DKIM)
	a.FromDomain = fromDomain
	a.Senders = senderDomains(m, fromDomain, a.MailFrom, a.DKIM)
	a.Groups = headerGroups(m, a.DKIM)

	receivers := receivingProviders(hops, a.Source)
	a.Spam = spamReports(m, a.Source, receivers)
	for _, r := range mailauth.ProviderResults(m) {
		a.Provider = append(a.Provider, providerView{ProviderResult: r, Trusted: trustedResult(r, receivers)})
	}
	dkim := mailauth.ResultNone
	for i, d := range a.DKIM {
		if i == 0 || d.Result == mailauth.ResultPass {
			dkim = d.Result
		}
		if d.Result == mailauth.ResultPass {
			break
		}
	}
	// A valid ARC chain first sealed by a receiving provider keeps the
	// results it recorded before the mail was forwarded.
	provider := a.Provider
	if original := a.ARC.OriginalResults(); original != nil && receivers[providerOf(a.ARC.Sets[0].Sealer)] {
		for _, r := range original {
			r.Server = r.Server + " (scellé ARC)"
			provider = append(provider, providerView{ProviderResult: r, Trusted: true})
		}
	}
	a.Verdicts = []authVerdict{
		verdict("SPF", "spf", a.SPF.Result, provider),
		verdict("DKIM", "dkim", dkim, provider),
		verdict("DMARC", "dmarc", a.DMARC.Result, provider),
	}
	// A relay service authenticated by the receiving server sends on behalf
	// of its users: their address in the display name is expected.
	if dmarc := a.Verdicts[2]; dmarc.Result == mailauth.ResultPass && dmarc.Source != "vérification interne" {
		a.Relay = relayOf(fromDomain)
	}
	a.Checks = consistencyChecks(m, hops, a.Relay)
	return a
}

// HasWarnings tells whether a verdict carries a warning.
func (a headerAnalysis) HasWarnings() bool {
	for _, v := range a.Verdicts {
		if v.Warning != "" {
			return true
		}
	}
	return false
}

// providerView is a result written by a server the mail went through.
// Trusted is set when that server is one of the receiving servers: anyone
// can write such headers in the mail before sending it.
type providerView struct {
	mailauth.ProviderResult
	Trusted bool
}

// authVerdict is the result shown for SPF, DKIM or DMARC.
type authVerdict struct {
	Name   string
	Result string
	Level  string
	// Source tells who produced Result: the receiving server or the internal
	// verification.
	Source   string
	Internal string
	Warning  string
}

// verdict trusts first the result written by the receiving provider: it
// checked the mail as received, with the DNS records of that time. The
// internal verification works on the mail as forwarded or exported, which
// providers often rebuild (Proton Mail, Exchange, Outlook .msg...), so its
// failures are warnings.
func verdict(name, method, internal string, provider []providerView) authVerdict {
	v := authVerdict{Name: name, Internal: internal}
	for _, p := range provider {
		if !p.Trusted || p.Method != method {
			continue
		}
		v.Result, v.Source = p.Result, "serveur de réception "+p.Server
		if p.Server == "" {
			v.Source = "serveur de réception"
		}
		v.Level = resultClass(p.Result)
		if p.Result == mailauth.ResultPass && failed(internal) {
			v.Warning = fmt.Sprintf("Validé à la réception, mais la vérification interne donne « %s » : le mail a probablement été modifié "+
				"depuis (export, transfert, conversion). Restez prudent.", internal)
		}
		return v
	}

	v.Result, v.Source = internal, "vérification interne"
	switch {
	case internal == mailauth.ResultPass:
		v.Level = "ok"
	case failed(internal):
		v.Level = levelWarning
		v.Warning = fmt.Sprintf("La vérification interne donne « %s » et aucun serveur de réception ne confirme le résultat : "+
			"le mail a pu être modifié lors de son transfert ou de son export, ou être falsifié. Restez prudent.", internal)
	default:
		v.Level = levelInfo
	}
	return v
}

// failed reports whether a check ran and failed ("none" and "neutral" mean
// there was nothing to check).
func failed(result string) bool {
	switch result {
	case mailauth.ResultFail, mailauth.ResultSoftFail, mailauth.ResultPermError, mailauth.ResultTempError:
		return true
	}
	return false
}

// sameProvider groups the domains a provider uses for its servers and its
// Authentication-Results.
var sameProvider = map[string]string{
	"outlook.com": "microsoft", "office365.com": "microsoft", "microsoft.com": "microsoft", "exchangelabs.com": "microsoft",
	"google.com": "google", "gmail.com": "google", "googlemail.com": "google",
	"protonmail.ch": "proton", "protonmail.com": "proton", "proton.me": "proton", "proton.ch": "proton",
}

func providerOf(host string) string {
	org := mailauth.OrgDomain(host)
	if p, ok := sameProvider[org]; ok {
		return p
	}
	return org
}

// receivingProviders returns the providers of the servers that received the
// mail from the sender's server onwards.
func receivingProviders(hops []mailauth.Hop, source int) map[string]bool {
	providers := map[string]bool{}
	for i := max(source, 0); i < len(hops); i++ {
		if by := hops[i].By; strings.Contains(by, ".") && net.ParseIP(by) == nil {
			providers[providerOf(by)] = true
		}
	}
	return providers
}

// trustedResult reports whether a result was written by a receiving server.
// Microsoft 365 writes no server name (nor does Received-SPF): such results
// are only trusted when Microsoft received the mail.
func trustedResult(r mailauth.ProviderResult, receivers map[string]bool) bool {
	if r.Server == "" {
		return receivers["microsoft"]
	}
	return receivers[providerOf(r.Server)]
}

func isPublicHop(h mailauth.Hop) bool {
	ip := h.IP
	return ip.IsValid() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

var wordDecoder = &mime.WordDecoder{}

var emailInText = regexp.MustCompile(`[^\s<>"',;:()@]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})`)

// consistencyChecks lists what in the headers may deceive the reader.
// relay is the authenticated service sending on behalf of a user, whose
// address then appears in the display name and the Reply-To.
func consistencyChecks(m mailauth.Message, hops []mailauth.Hop, relay *relayService) []LinkWarning {
	var checks []LinkWarning
	add := func(level, format string, args ...any) {
		checks = append(checks, LinkWarning{level, fmt.Sprintf(format, args...)})
	}
	parser := &mail.AddressParser{WordDecoder: wordDecoder}

	from, err := parser.ParseList(m.Get("From"))
	switch {
	case err != nil || len(from) == 0:
		add(levelWarning, "En-tête From absent ou illisible : l'expéditeur ne peut pas être vérifié")
		return checks
	case len(from) > 1:
		add(levelWarning, "Plusieurs expéditeurs dans l'en-tête From")
	}
	sender := from[0]
	senderDomain := domainOfAddress(sender.Address)
	senderOrg := mailauth.OrgDomain(senderDomain)

	// "support@bank.com" <x@evil.example>
	onBehalf := map[string]bool{}
	for _, match := range emailInText.FindAllStringSubmatch(sender.Name, -1) {
		if mailauth.OrgDomain(match[1]) != senderOrg && relay != nil {
			add(levelInfo, "Envoyé par %s pour le compte de %s : le service est authentifié, l'adresse %s est celle déclarée à ce service",
				relay.Name, match[0], match[0])
			onBehalf[strings.ToLower(match[0])] = true
		} else if mailauth.OrgDomain(match[1]) != senderOrg {
			add(levelDanger, "Le nom affiché « %s » contient l'adresse %s, mais l'expéditeur réel est %s", sender.Name, match[0], sender.Address)
		}
	}
	if !strings.Contains(sender.Name, "@") {
		for _, word := range strings.Fields(sender.Name) {
			if shown := displayedHost(word); shown != "" && mailauth.OrgDomain(shown) != senderOrg {
				add(levelWarning, "Le nom affiché « %s » évoque le domaine %s, mais l'adresse réelle est %s", sender.Name, displayHost(shown), sender.Address)
			}
		}
	}

	if replyTo, err := parser.ParseList(m.Get("Reply-To")); err == nil {
		for _, address := range replyTo {
			switch d := domainOfAddress(address.Address); {
			case mailauth.OrgDomain(d) == senderOrg:
			case onBehalf[strings.ToLower(address.Address)]:
				add(levelInfo, "Les réponses partiront vers %s (Reply-To), le compte pour lequel %s a envoyé le message", address.Address, relay.Name)
			default:
				add(levelWarning, "Les réponses partiront vers %s (Reply-To), un autre domaine que l'expéditeur", address.Address)
			}
		}
	}
	if returnPath := strings.Trim(m.Get("Return-Path"), "<> "); returnPath != "" {
		if d := domainOfAddress(returnPath); mailauth.OrgDomain(d) != senderOrg {
			add(levelInfo, "Adresse de retour (Return-Path) sur le domaine %s : fréquent pour les envois par une plateforme d'emailing", d)
		}
	}
	if messageID := m.Get("Message-ID"); messageID == "" {
		add(levelWarning, "Pas d'identifiant Message-ID : inhabituel pour un vrai serveur de messagerie")
	} else if d := domainOfAddress(strings.Trim(messageID, "<>")); d != "" && mailauth.OrgDomain(d) != senderOrg {
		add(levelInfo, "Identifiant Message-ID créé par le domaine %s", d)
	}

	date, err := mail.ParseDate(m.Get("Date"))
	if err != nil {
		add(levelWarning, "Date absente ou invalide")
	} else if len(hops) > 0 && !hops[len(hops)-1].Date.IsZero() {
		if skew := hops[len(hops)-1].Date.Sub(date); skew > 24*time.Hour || skew < -time.Hour {
			add(levelInfo, "La date annoncée (%s) est éloignée de la date de réception (%s)",
				date.Local().Format("02.01.2006 15:04"), hops[len(hops)-1].Date.Local().Format("02.01.2006 15:04"))
		}
	}
	return checks
}

func domainOfAddress(address string) string {
	i := strings.LastIndexByte(address, '@')
	if i < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(address[i+1:], "."))
}

// resultClass maps an authentication result to a level of the page.
func resultClass(result string) string {
	switch result {
	case mailauth.ResultPass:
		return "ok"
	case mailauth.ResultFail, mailauth.ResultPermError:
		return levelDanger
	case mailauth.ResultSoftFail, mailauth.ResultTempError:
		return levelWarning
	}
	return levelInfo
}

// senderDomains lists the domains that name the sender, From first.
func senderDomains(m mailauth.Message, from, mailFrom string, dkim []mailauth.DKIMResult) []subject {
	var subjects []subject
	seen := map[string]bool{}
	add := func(domain, role string) {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if domain != "" && !seen[domain+role] {
			seen[domain+role] = true
			subjects = append(subjects, subject{domain, role})
		}
	}
	add(from, "expéditeur (From)")
	if replyTo, err := (&mail.AddressParser{WordDecoder: wordDecoder}).ParseList(m.Get("Reply-To")); err == nil {
		for _, address := range replyTo {
			add(domainOfAddress(address.Address), "adresse de réponse (Reply-To)")
		}
	}
	add(domainOfAddress(mailFrom), "adresse de retour (Return-Path)")
	for _, d := range dkim {
		add(d.Domain, "signataire DKIM")
	}
	return subjects
}
