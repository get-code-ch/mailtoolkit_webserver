package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// Traffic light colors of the risk assessment.
const (
	riskGreen  = "green"
	riskOrange = "orange"
	riskRed    = "red"
)

// riskReport sums up the analysis for a visitor without technical
// knowledge: a traffic light, the reasons in plain words, and what to do.
type riskReport struct {
	Light    string
	Score    int
	Headline string
	Advice   string
	Reasons  []riskReason
	// Positives are the reassuring findings.
	Positives []string
	// Sender is the displayed sender, Authenticated whether the mail
	// really comes from its domain.
	Sender        string
	Authenticated bool
}

// riskReason is one doubtful element of the mail.
type riskReason struct {
	Level string
	// Weight counts in the score; 3 or more alone turns the light red.
	Weight int
	// Simple explains it in plain words, Detail gives the technical fact.
	Simple string
	Detail string
	// Anchor points to the detailed analysis.
	Anchor string
}

// Level maps the light to the page levels.
func (r riskReport) Level() string {
	switch r.Light {
	case riskRed:
		return levelDanger
	case riskOrange:
		return levelWarning
	}
	return "ok"
}

// riskInput gathers the analyses of a mail.
type riskInput struct {
	Auth        *headerAnalysis
	Links       []Link
	Attachments []attachmentView
	Reputation  reputation
	Lookalikes  []lookalike
}

// assessRisk turns the analyses into a traffic light.
func assessRisk(in riskInput) riskReport {
	var r riskReport
	add := func(level string, weight int, anchor, simple, detail string) {
		// The same explanation is given once, its details gathered.
		for i := range r.Reasons {
			if r.Reasons[i].Simple == simple {
				if detail != "" {
					r.Reasons[i].Detail += " · " + detail
				}
				return
			}
		}
		r.Reasons = append(r.Reasons, riskReason{Level: level, Weight: weight, Simple: simple, Detail: detail, Anchor: anchor})
	}

	if a := in.Auth; a != nil {
		assessAuthentication(&r, a, add)
		for _, check := range a.Checks {
			switch check.Level {
			case levelDanger:
				add(levelDanger, 3, "headers", "Le nom affiché de l'expéditeur cherche à faire croire à une autre adresse que la vraie.", check.Message)
			case levelWarning:
				add(levelWarning, 1, "headers", "Les adresses du message ne sont pas cohérentes entre elles.", check.Message)
			}
		}
		for _, s := range a.Spam {
			if !s.Trusted || s.Outbound {
				continue
			}
			switch s.Level {
			case levelDanger:
				add(levelDanger, 4, "antispam", "Le filtre de votre messagerie a classé ce message comme dangereux ("+s.Verdict+").",
					s.Filter+" : "+s.Verdict)
			case levelWarning:
				add(levelWarning, 2, "antispam", "Le filtre de votre messagerie a classé ce message comme indésirable ("+s.Verdict+").",
					s.Filter+" : "+s.Verdict)
			case "ok":
				r.Positives = append(r.Positives, "Le filtre antispam de votre messagerie ("+s.Filter+") n'a rien trouvé à redire.")
			}
		}
	}

	assessLinks(&r, in.Links, add)
	assessAttachments(&r, in.Attachments, add)

	// An authenticated mail from a brand links to its other domains:
	// only real lookalikes count then.
	senderBrand := ""
	if r.Authenticated {
		org := mailauth.OrgDomain(r.Sender)
		for _, b := range brands {
			if official(org, b) {
				senderBrand = b.Name
			}
		}
	}
	linkNames := 0
	for _, l := range in.Lookalikes {
		if l.Kind != "sosie" && l.Brand == senderBrand {
			continue
		}
		if l.Kind != "sosie" && l.Role == "lien" {
			// The brand name in a link domain is frequent in legitimate
			// mails (campaign sites): weak signal, counted once.
			linkNames++
			weight := 0
			if linkNames == 1 {
				weight = 1
			}
			add(levelWarning, weight, "reputation", fmt.Sprintf("Un lien mène vers %s, qui utilise le nom %s sans lui appartenir.", l.Domain, l.Brand),
				fmt.Sprintf("%s %s", l.Domain, l.Reason))
			continue
		}
		if l.Kind == "sosie" {
			add(levelDanger, 4, "reputation", fmt.Sprintf("L'adresse %s imite %s : c'est une technique classique d'hameçonnage.", l.Domain, l.Brand),
				fmt.Sprintf("%s (%s) %s", l.Domain, l.Role, l.Reason))
		} else {
			add(levelWarning, 2, "reputation", fmt.Sprintf("L'adresse %s utilise le nom %s sans lui appartenir.", l.Domain, l.Brand),
				fmt.Sprintf("%s (%s) %s", l.Domain, l.Role, l.Reason))
		}
	}
	for _, l := range in.Reputation.Listings {
		simple := fmt.Sprintf("%s figure sur une liste noire de sites et serveurs malveillants.", l.Subject)
		if l.Level == levelDanger {
			add(levelDanger, 3, "reputation", simple, fmt.Sprintf("%s (%s) : %s, %s", l.Subject, l.Role, l.List, l.Meaning))
		} else {
			add(levelWarning, 1, "reputation", simple, fmt.Sprintf("%s (%s) : %s, %s", l.Subject, l.Role, l.List, l.Meaning))
		}
	}
	for _, d := range in.Reputation.Domains {
		switch d.Level() {
		case levelDanger:
			add(levelDanger, 3, "reputation", fmt.Sprintf("Le site %s a été créé il y a seulement %d jours : les escrocs utilisent des sites tout neufs.", d.Domain, d.Days()),
				fmt.Sprintf("%s (%s) enregistré le %s", d.Domain, d.Role, d.DateText()))
		case levelWarning:
			add(levelWarning, 1, "reputation", fmt.Sprintf("Le site %s est récent (créé il y a %d jours).", d.Domain, d.Days()),
				fmt.Sprintf("%s (%s) enregistré le %s", d.Domain, d.Role, d.DateText()))
		}
	}

	slices.SortStableFunc(r.Reasons, func(a, b riskReason) int { return b.Weight - a.Weight })
	critical := false
	for _, reason := range r.Reasons {
		r.Score += reason.Weight
		critical = critical || reason.Weight >= 3
	}
	switch {
	case critical || r.Score >= 5:
		r.Light = riskRed
		r.Headline = "Ce message est probablement dangereux"
		r.Advice = "Ne cliquez sur aucun lien, n'ouvrez pas les pièces jointes, ne répondez pas et ne communiquez aucune information " +
			"(mot de passe, code, coordonnées bancaires). Supprimez le message ou signalez-le à votre service informatique."
	case r.Score >= 2:
		r.Light = riskOrange
		r.Headline = "Ce message présente des éléments suspects"
		r.Advice = "Soyez prudent : avant de cliquer ou de répondre, vérifiez la demande par un autre moyen, par exemple en appelant " +
			"l'expéditeur ou en tapant vous-même l'adresse de son site officiel."
	default:
		r.Light = riskGreen
		r.Headline = "Aucun élément suspect détecté"
		r.Advice = "Rien d'inquiétant n'a été trouvé. Restez attentif : aucune analyse n'est infaillible, surtout si le message " +
			"vous demande de l'argent, un mot de passe ou une action urgente."
	}
	return r
}

// assessAuthentication tells whether the mail really comes from the
// displayed sender.
func assessAuthentication(r *riskReport, a *headerAnalysis, add func(level string, weight int, anchor, simple, detail string)) {
	r.Sender = a.FromDomain
	var dmarc, dkim, spf authVerdict
	for _, v := range a.Verdicts {
		switch v.Name {
		case "DMARC":
			dmarc = v
		case "DKIM":
			dkim = v
		case "SPF":
			spf = v
		}
	}
	switch {
	case dmarc.Result == mailauth.ResultPass:
		r.Authenticated = true
		r.Positives = append(r.Positives, fmt.Sprintf("Le message provient bien du domaine de l'expéditeur affiché (%s).", a.FromDomain))
	case dmarc.Result == mailauth.ResultFail && dmarc.Source != "vérification interne":
		add(levelDanger, 4, "dmarc", fmt.Sprintf("Votre messagerie a constaté que ce message ne vient pas vraiment de %s, l'expéditeur affiché.", a.FromDomain),
			"DMARC fail ("+dmarc.Source+")")
	case dmarc.Result == mailauth.ResultFail:
		add(levelWarning, 2, "dmarc", fmt.Sprintf("Impossible de confirmer que ce message vient vraiment de %s.", a.FromDomain),
			"DMARC fail (vérification interne : le message a pu être modifié par le transfert)")
	case dkim.Result == mailauth.ResultPass || spf.Result == mailauth.ResultPass:
		// Authenticated, but not for the displayed domain: frequent with
		// mailing services, says little.
	default:
		add(levelWarning, 1, "dmarc", "Rien ne prouve que ce message vient bien de l'expéditeur affiché : il n'est pas authentifié.",
			"aucune authentification SPF, DKIM ou DMARC valide")
	}
}

// assessLinks reports the deceptive links.
func assessLinks(r *riskReport, links []Link, add func(level string, weight int, anchor, simple, detail string)) {
	dangers, warnings := 0, 0
	for _, l := range links {
		var first string
		for _, w := range l.Warnings {
			if w.Level == l.Level() {
				first = w.Message
				break
			}
		}
		switch l.Level() {
		case levelDanger:
			dangers++
			if dangers <= 3 {
				add(levelDanger, 3, "links", "Un lien est piégé : "+lowerFirst(first), l.URL)
			}
		case levelWarning:
			warnings++
			if warnings <= 2 {
				add(levelWarning, 1, "links", "Un lien est suspect : "+lowerFirst(first), l.URL)
			}
		}
	}
	if dangers > 3 {
		add(levelDanger, 0, "links", fmt.Sprintf("Et %d autres liens piégés.", dangers-3), "")
	}
	if len(links) > 0 && dangers == 0 && warnings == 0 {
		r.Positives = append(r.Positives, "Aucun lien trompeur n'a été trouvé.")
	}
}

// assessAttachments reports the dangerous attachments.
func assessAttachments(r *riskReport, attachments []attachmentView, add func(level string, weight int, anchor, simple, detail string)) {
	clean := true
	for _, a := range attachments {
		var first string
		for _, alert := range a.Alerts {
			if alert.Level == a.Level() {
				first = alert.Message
				break
			}
		}
		switch a.Level() {
		case levelDanger:
			clean = false
			add(levelDanger, 4, "attachments", fmt.Sprintf("La pièce jointe « %s » est dangereuse : ne l'ouvrez pas.", a.Name), first)
		case levelWarning:
			clean = false
			add(levelWarning, 2, "attachments", fmt.Sprintf("La pièce jointe « %s » demande de la prudence.", a.Name), first)
		}
	}
	if len(attachments) > 0 && clean {
		r.Positives = append(r.Positives, "Les pièces jointes ne contiennent rien de dangereux détectable.")
	}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if len(r) > 1 && r[1] >= 'A' && r[1] <= 'Z' {
		return s // acronym
	}
	return strings.ToLower(string(r[:1])) + string(r[1:])
}

// linkSubjects returns the domains of the links, the dangerous ones first,
// for the reputation checks; hosts are kept for the lookalike checks.
func linkSubjects(links []Link) (domains, hosts []subject) {
	ordered := slices.Clone(links)
	slices.SortStableFunc(ordered, func(a, b Link) int { return spamSeverity[b.Level()] - spamSeverity[a.Level()] })
	seen := map[string]bool{}
	for _, l := range ordered {
		host := linkHost(l.URL)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, subject{host, "lien"})
		if org := mailauth.OrgDomain(host); org != "" && !seen["org:"+org] {
			seen["org:"+org] = true
			domains = append(domains, subject{org, "lien"})
		}
	}
	return domains, hosts
}

// linkHost returns the ASCII host name of a URL, "" for IP addresses and
// URLs without host. For mailto: links, the domain of the address.
func linkHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if u.Scheme == "mailto" {
		host = domainOfAddress(u.Opaque)
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); host == "" || err == nil {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(host))
	if err != nil || !strings.Contains(ascii, ".") {
		return ""
	}
	return ascii
}
