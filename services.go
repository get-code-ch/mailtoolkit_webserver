package main

import (
	"slices"
	"strings"

	"github.com/get-code-ch/mailtoolkit_webserver/smime"
)

// externalService is a service the server relies on, described on the
// security page and in the analyses.
type externalService struct {
	Name string
	// Checks tells what the service is used for, Sent what it receives.
	Checks string
	Sent   string
	Site   string
	// Enabled is false when the service is not configured on this server.
	Enabled bool
	// Note qualifies the use of the service on this server.
	Note string
}

// externalServices lists the services of this server, enabled or not.
func (s *server) externalServices() []externalService {
	var keys ThreatIntelConfig
	if s.threats != nil {
		keys = s.threats.config
	}
	rep := s.reputation != nil
	var zones []string
	if rep {
		zones = append(slices.Clone(s.reputation.ipLists), s.reputation.domainLists...)
	}
	uses := func(service string) bool {
		return slices.ContainsFunc(zones, func(z string) bool { return listService(z) == service })
	}
	spamhaus := "requêtes DNS publiques, souvent refusées depuis un hébergeur"
	if slices.ContainsFunc(zones, func(z string) bool { return strings.HasSuffix(z, ".dq.spamhaus.net") }) {
		spamhaus = "Data Query Service (clé DQS)"
	}
	services := []externalService{
		{Name: "URLhaus", Checks: "sites de distribution de logiciels malveillants", Sent: "noms des sites des liens, adresses des plateformes partagées sans paramètres",
			Site: "https://urlhaus.abuse.ch/", Enabled: keys.AbuseCHKey != ""},
		{Name: "MalwareBazaar", Checks: "fichiers malveillants connus", Sent: "empreintes SHA-256 des pièces jointes",
			Site: "https://bazaar.abuse.ch/", Enabled: keys.AbuseCHKey != ""},
		{Name: "Google Safe Browsing", Checks: "sites d'hameçonnage et de logiciels malveillants", Sent: "noms des sites des liens, adresses des plateformes partagées sans paramètres",
			Site: "https://safebrowsing.google.com/", Enabled: keys.SafeBrowsingKey != ""},
		{Name: "VirusTotal", Checks: "verdicts de dizaines d'antivirus", Sent: "empreintes SHA-256 des pièces jointes, domaines des liens",
			Site: "https://www.virustotal.com/", Enabled: keys.VirusTotalKey != ""},
		{Name: "Spamhaus ZEN", Checks: "serveurs d'envoi de spam", Sent: "adresse IP du serveur d'envoi",
			Site: "https://www.spamhaus.org/", Enabled: uses("Spamhaus ZEN"), Note: spamhaus},
		{Name: "Spamhaus DBL", Checks: "domaines de spam et d'hameçonnage", Sent: "domaines de l'expéditeur et des liens",
			Site: "https://www.spamhaus.org/", Enabled: uses("Spamhaus DBL"), Note: spamhaus},
		{Name: "SpamCop", Checks: "serveurs d'envoi de spam", Sent: "adresse IP du serveur d'envoi",
			Site: "https://www.spamcop.net/", Enabled: uses("SpamCop")},
		{Name: "SURBL", Checks: "domaines de spam et d'hameçonnage", Sent: "domaines de l'expéditeur et des liens",
			Site: "https://www.surbl.org/", Enabled: uses("SURBL")},
		{Name: rdapService, Checks: "date d'enregistrement des domaines", Sent: "domaines de l'expéditeur et des liens",
			Site: "https://data.iana.org/rdap/", Enabled: rep && s.reputation.rdap != nil},
		{Name: "Autorités de certification", Checks: "révocation des certificats S/MIME (OCSP, CRL)", Sent: "numéro de série du certificat de l'expéditeur",
			Enabled: s.smime != nil && s.smime.Revocation != nil},
		{Name: "Sites des liens", Checks: "page finale des liens suspects", Sent: "une visite depuis l'adresse du serveur, sans cookie",
			Enabled: s.visitor != nil, Note: "les liens à usage unique (désinscription, confirmation) ne sont jamais suivis"},
	}
	return services
}

// servicesReport is what the external services were asked about a mail.
type servicesReport struct {
	Lookups []serviceLookup
	// Visited counts the links followed automatically.
	Visited int
	// Revocation is the method used to check the S/MIME certificate.
	Revocation string
	// Off are the services not configured on this server.
	Off []string
}

// Names lists the services consulted.
func (r servicesReport) Names() []string {
	var names []string
	for _, l := range r.Lookups {
		names = append(names, l.Service)
	}
	if r.Revocation != "" {
		names = append(names, "autorité de certification")
	}
	return names
}

func (s *server) servicesReport(threats threatReport, rep reputation, links []Link, signature smime.Result) servicesReport {
	report := servicesReport{Lookups: append(slices.Clone(threats.Lookups), rep.Lookups...)}
	for _, l := range links {
		if l.Visit != nil && !l.Visit.Manual {
			report.Visited++
		}
	}
	if signature.Revocation.Method != "" {
		report.Revocation = strings.TrimSpace(signature.Revocation.Method + " " + signature.Revocation.Source)
	}
	for _, service := range s.externalServices() {
		if !service.Enabled {
			report.Off = append(report.Off, service.Name)
		}
	}
	return report
}
