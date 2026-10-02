package main

import (
	"context"
	"fmt"
	"mime"
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
	Provider []mailauth.ProviderResult
	Checks   []LinkWarning
	Fields   []mailauth.Field
	// Part is the content part shown with the analysis, kept in the links
	// choosing another hop.
	Part string
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
		Provider: mailauth.ProviderResults(m),
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

	fromDomain := ""
	if from, err := (&mail.AddressParser{WordDecoder: wordDecoder}).ParseList(m.Get("From")); err == nil && len(from) == 1 {
		fromDomain = domainOfAddress(from[0].Address)
	}
	a.DMARC = mailauth.CheckDMARC(ctx, resolver, fromDomain, a.SPF, a.DKIM)
	a.Checks = consistencyChecks(m, hops)
	return a
}

func isPublicHop(h mailauth.Hop) bool {
	ip := h.IP
	return ip.IsValid() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

var wordDecoder = &mime.WordDecoder{}

var emailInText = regexp.MustCompile(`[^\s<>"',;:()@]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})`)

// consistencyChecks lists what in the headers may deceive the reader.
func consistencyChecks(m mailauth.Message, hops []mailauth.Hop) []LinkWarning {
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
	for _, match := range emailInText.FindAllStringSubmatch(sender.Name, -1) {
		if mailauth.OrgDomain(match[1]) != senderOrg {
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
			if d := domainOfAddress(address.Address); mailauth.OrgDomain(d) != senderOrg {
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
