package main

import (
	"slices"
	"strings"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// brand is an often impersonated organization, with its official domains.
type brand struct {
	Name    string
	Label   string
	Domains []string
}

// ownBrands turns the trusted domains into brands: fraudsters imitate the
// organization's domain to pose as a colleague or its IT department.
func ownBrands(trusted []string) []brand {
	var own []brand
	for _, t := range trusted {
		org := mailauth.OrgDomain(t)
		label, _, _ := strings.Cut(org, ".")
		if len(label) < 4 {
			continue // too short to be recognized without false alarms
		}
		own = append(own, brand{org, label, []string{org}})
	}
	return own
}

// microsoftDomains are the domains Microsoft sends from or links to.
var microsoftDomains = []string{"microsoft.com", "microsoft.ch", "microsoftonline.com", "office.com", "office365.com", "outlook.com",
	"live.com", "sharepoint.com", "microsoft365.com", "windows.net", "azure.com", "msft.net", "onmicrosoft.com", "mail.microsoft",
	"cloud.microsoft", "onedrive.com", "1drv.ms", "skype.com", "teams.microsoft.com", "microsoftstore.com"}

// brands are frequent phishing targets, in Switzerland and worldwide.
var brands = []brand{
	{"PayPal", "paypal", []string{"paypal.com", "paypal.ch", "paypal.me", "paypalobjects.com", "paypal-communication.com"}},
	{"Microsoft", "microsoft", microsoftDomains},
	{"SharePoint", "sharepoint", microsoftDomains},
	{"OneDrive", "onedrive", microsoftDomains},
	{"Outlook", "outlook", []string{"outlook.com", "office.com", "office365.com", "microsoft.com"}},
	{"Apple", "apple", []string{"apple.com", "icloud.com", "me.com", "apple.ch"}},
	{"iCloud", "icloud", []string{"icloud.com", "apple.com"}},
	{"Google", "google", []string{"google.com", "google.ch", "gmail.com", "googlemail.com", "youtube.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "withgoogle.com", "g.co"}},
	{"Gmail", "gmail", []string{"gmail.com", "google.com"}},
	{"Amazon", "amazon", []string{"amazon.com", "amazon.de", "amazon.fr", "amazon.it", "amazon.co.uk", "amazon.ch", "amazonaws.com", "amazonses.com", "a2z.com"}},
	{"Netflix", "netflix", []string{"netflix.com", "netflix.net"}},
	{"Facebook", "facebook", []string{"facebook.com", "facebookmail.com", "fb.com", "meta.com"}},
	{"Instagram", "instagram", []string{"instagram.com", "facebookmail.com"}},
	{"WhatsApp", "whatsapp", []string{"whatsapp.com", "whatsapp.net"}},
	{"LinkedIn", "linkedin", []string{"linkedin.com", "licdn.com"}},
	{"DHL", "dhl", []string{"dhl.com", "dhl.ch", "dhl.de"}},
	{"UPS", "ups", []string{"ups.com"}},
	{"FedEx", "fedex", []string{"fedex.com"}},
	{"DPD", "dpd", []string{"dpd.com", "dpd.ch", "dpd.de"}},
	{"PostFinance", "postfinance", []string{"postfinance.ch"}},
	{"La Poste suisse", "swisspost", []string{"post.ch", "swisspost.ch"}},
	{"Swisscom", "swisscom", []string{"swisscom.ch", "swisscom.com", "bluewin.ch"}},
	{"Bluewin", "bluewin", []string{"bluewin.ch", "swisscom.ch"}},
	{"Sunrise", "sunrise", []string{"sunrise.ch"}},
	{"UBS", "ubs", []string{"ubs.com", "ubs.ch"}},
	{"Raiffeisen", "raiffeisen", []string{"raiffeisen.ch"}},
	{"Credit Suisse", "creditsuisse", []string{"credit-suisse.com", "ubs.com"}},
	{"TWINT", "twint", []string{"twint.ch"}},
	{"Migros", "migros", []string{"migros.ch", "migros.com", "migrosbank.ch", "migrosmagazine.ch"}},
	{"CFF / SBB", "sbb", []string{"sbb.ch", "cff.ch", "ffs.ch"}},
	{"SwissPass", "swisspass", []string{"swisspass.ch", "sbb.ch"}},
	{"Ricardo", "ricardo", []string{"ricardo.ch"}},
	{"Galaxus", "galaxus", []string{"galaxus.ch", "galaxus.de", "digitecgalaxus.ch"}},
	{"Digitec", "digitec", []string{"digitec.ch", "digitecgalaxus.ch"}},
	{"Proton", "protonmail", []string{"proton.me", "protonmail.com", "protonmail.ch", "proton.ch"}},
	{"DocuSign", "docusign", []string{"docusign.com", "docusign.net"}},
	{"Dropbox", "dropbox", []string{"dropbox.com", "dropboxmail.com"}},
	{"WeTransfer", "wetransfer", []string{"wetransfer.com"}},
	{"Adobe", "adobe", []string{"adobe.com", "adobesign.com", "adobe.io"}},
	{"Booking.com", "booking", []string{"booking.com"}},
	{"Airbnb", "airbnb", []string{"airbnb.com", "airbnb.ch"}},
	{"Visa", "visa", []string{"visa.com", "visa.ch"}},
	{"Mastercard", "mastercard", []string{"mastercard.com", "mastercard.ch"}},
	{"Binance", "binance", []string{"binance.com"}},
	{"Coinbase", "coinbase", []string{"coinbase.com"}},
	{"Ledger", "ledger", []string{"ledger.com"}},
}

// lookalike is a domain that imitates a brand.
type lookalike struct {
	Domain string
	Role   string
	Brand  string
	// Kind is "sosie" (a lookalike of the brand domain) or "nom" (the brand
	// name inside another domain).
	Kind   string
	Reason string
	Level  string
	// Own is set when the domain imitates the organization itself.
	Own bool
}

// confusables are the substitutions used to imitate a name.
var confusables = strings.NewReplacer("rn", "m", "vv", "w", "0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t", "8", "b", "-", "", "_", "")

// findLookalikes checks the organizational domains of a mail against the
// brands and the organization's own domains. host is the full name
// (subdomains included).
func findLookalikes(subjects []subject, trusted []string) []lookalike {
	own := ownBrands(trusted)
	var found []lookalike
	seen := map[string]bool{}
	for _, s := range subjects {
		host := strings.ToLower(strings.TrimSuffix(s.Value, "."))
		org := mailauth.OrgDomain(host)
		if org == "" || seen[host] {
			continue
		}
		seen[host] = true
		if official(org, own...) {
			continue
		}
		l, ok := checkLookalike(host, org, own)
		if ok {
			l.Own = true
		} else {
			l, ok = checkLookalike(host, org, brands)
		}
		if ok {
			l.Role = s.Role
			found = append(found, l)
		}
	}
	return found
}

func checkLookalike(host, org string, list []brand) (lookalike, bool) {
	label, _, _ := strings.Cut(org, ".")
	if official(org, list...) || officialHost(host, list) {
		return lookalike{}, false
	}
	for _, b := range list {
		l := lookalike{Domain: host, Brand: b.Name}
		switch {
		case label == b.Label:
			l.Kind, l.Level = "nom", levelWarning
			l.Reason = "porte exactement le nom de " + b.Name + " mais avec une extension qui n'est pas l'une des siennes"
		case confusables.Replace(label) == strings.ReplaceAll(b.Label, "-", ""):
			l.Kind, l.Level = "sosie", levelDanger
			l.Reason = "imite " + b.Name + " en remplaçant des lettres par des caractères qui leur ressemblent"
		case len(b.Label) >= 5 && editDistance(strings.ReplaceAll(label, "-", ""), strings.ReplaceAll(b.Label, "-", "")) == 1:
			l.Kind, l.Level = "sosie", levelDanger
			l.Reason = "ne diffère de " + b.Name + " que d'une lettre"
		case containsWord(label, b.Label):
			l.Kind, l.Level = "nom", levelWarning
			l.Reason = "contient le nom " + b.Name + " sans appartenir à " + b.Name
		case containsWord(strings.TrimSuffix(host, "."+org), b.Label):
			l.Kind, l.Level = "nom", levelWarning
			l.Reason = "utilise le nom " + b.Name + " en sous-domaine d'un domaine qui ne lui appartient pas (" + org + ")"
		default:
			continue
		}
		return l, true
	}
	return lookalike{}, false
}

// officialHost reports whether host is under a domain of one of the
// brands, for the domains the public suffix list splits
// (fonts.googleapis.com).
func officialHost(host string, list []brand) bool {
	for _, b := range list {
		for _, d := range b.Domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}
	return false
}

// official reports whether org is a domain of one of the brands.
func official(org string, list ...brand) bool {
	for _, b := range list {
		if slices.Contains(b.Domains, org) {
			return true
		}
	}
	return false
}

// containsWord reports whether name appears in s as a word: delimited by
// dots, hyphens or digits, or long enough not to match by chance.
func containsWord(s, name string) bool {
	if s == "" {
		return false
	}
	if len(name) >= 6 {
		return strings.Contains(s, name)
	}
	for _, word := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') }) {
		if word == name {
			return true
		}
	}
	return false
}

// editDistance is the Damerau-Levenshtein distance (adjacent swaps count
// as one edit).
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
