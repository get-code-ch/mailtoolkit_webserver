package main

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/text/unicode/norm"
)

// Social engineering cues of fraud mails, in French, German, English and
// Italian. Phrases are written without accents, the text being normalized
// the same way.
const (
	cueUrgency      = "urgence"
	cuePayment      = "paiement"
	cueBankChange   = "changement de coordonnées bancaires"
	cueSecrecy      = "confidentialité"
	cueAvailability = "disponibilité"
	cueGiftCards    = "cartes cadeaux"
	cueCredentials  = "identifiants"
	cueThreat       = "menace"
	cueScan         = "scanner un code"
)

var cuePhrases = map[string][]string{
	cueUrgency: {
		"urgent", "urgente", "en urgence", "immediatement", "sans delai", "au plus vite", "des que possible", "dans les 24 heures",
		"dans les 48 heures", "aujourd'hui encore", "avant ce soir", "dringend", "dringende", "dringenden", "sofort", "umgehend", "unverzuglich", "heute noch",
		"innerhalb von 24 stunden", "asap", "immediately", "as soon as possible", "right away", "within 24 hours",
		"subito", "immediatamente", "entro oggi", "entro 24 ore", "al piu presto",
	},
	cuePayment: {
		"virement", "virements", "paiement", "payer", "versement", "transfert de fonds", "facture", "factures", "regler la facture",
		"uberweisung", "uberweisen", "zahlung", "uberweisungsauftrag", "rechnung", "begleichen", "wire transfer", "bank transfer",
		"payment", "invoice", "remittance", "bonifico", "pagamento", "fattura",
	},
	cueBankChange: {
		"nouvelles coordonnees bancaires", "nouvelle coordonnee bancaire", "changement de coordonnees bancaires",
		"modification de nos coordonnees bancaires", "changement de banque", "nouveau compte bancaire", "nouvel iban",
		"changement d'iban", "notre nouveau compte", "coordonnees bancaires ont change", "neue bankverbindung",
		"geanderte bankverbindung", "anderung der bankverbindung", "neues bankkonto", "neue iban", "kontowechsel",
		"new bank details", "updated bank details", "change of bank details", "changed our bank", "new account details",
		"new banking details", "nuove coordinate bancarie", "nuovo iban", "cambio di coordinate bancarie", "nuovo conto",
	},
	cueSecrecy: {
		"confidentiel", "strictement confidentiel", "en toute discretion", "ne pas en parler", "n'en parlez", "entre nous",
		"vertraulich", "vertrauliche", "vertraulichen", "streng vertraulich", "streng vertrauliche", "diskret", "niemandem davon", "confidential", "keep this between us",
		"do not discuss", "don't tell", "do not mention", "riservato", "confidenziale", "massima discrezione",
	},
	cueAvailability: {
		"etes-vous disponible", "es-tu disponible", "etes vous disponible", "avez-vous un moment", "as-tu un moment",
		"je suis en reunion", "je ne peux pas telephoner", "je ne suis pas joignable", "sind sie verfugbar", "bist du verfugbar",
		"haben sie kurz zeit", "hast du kurz zeit", "ich bin in einer sitzung", "ich bin im meeting", "are you available",
		"are you at your desk", "do you have a moment", "i'm in a meeting", "i am in a meeting", "can't talk", "cannot take calls",
		"sei disponibile", "e disponibile", "sono in riunione",
	},
	cueGiftCards: {
		"carte cadeau", "cartes cadeaux", "cartes-cadeaux", "carte-cadeau", "carte prepayee", "cartes prepayees",
		"geschenkkarte", "geschenkkarten", "gutscheinkarte", "gift card", "gift cards", "itunes", "google play card",
		"steam card", "paysafecard", "carta regalo", "carte regalo",
	},
	cueCredentials: {
		"mot de passe", "identifiants", "verifier votre compte", "verifiez votre compte", "confirmer votre compte",
		"confirmez votre identite", "reactiver votre compte", "double authentification", "authentification a deux facteurs",
		"passwort", "kennwort", "anmeldedaten", "zugangsdaten", "konto verifizieren", "bestatigen sie ihr konto",
		"zwei-faktor", "password", "verify your account", "confirm your account", "verify your identity", "credentials",
		"two-factor", "multi-factor", "mfa", "2fa", "credenziali", "verifica il tuo account", "conferma il tuo account",
	},
	cueThreat: {
		"compte suspendu", "compte bloque", "sera suspendu", "sera supprime", "sera desactive", "seront supprimes",
		"dernier rappel", "dernier avertissement", "boite de reception est pleine", "konto gesperrt",
		"wird gesperrt", "wird geloscht", "wird deaktiviert", "letzte mahnung", "letzte warnung", "account suspended",
		"account locked", "will be suspended", "will be deleted", "will be deactivated", "final notice", "final warning",
		"mailbox is full", "account sospeso", "sara sospeso", "sara disattivato", "ultimo avviso",
	},
	cueScan: {
		"scannez", "scanner le code", "scannez le code", "code qr", "qr code", "qr-code", "scannen sie", "scan the",
		"scan this", "scansiona", "scansionare",
	},
}

var cuePatterns = func() map[string]*regexp.Regexp {
	patterns := map[string]*regexp.Regexp{}
	for cue, phrases := range cuePhrases {
		quoted := make([]string, len(phrases))
		for i, p := range phrases {
			quoted[i] = regexp.QuoteMeta(p)
		}
		// Longest first, so that the match shows the whole phrase.
		slices.SortFunc(quoted, func(a, b string) int { return len(b) - len(a) })
		patterns[cue] = regexp.MustCompile(`(?:^|[^\p{L}\p{N}])(` + strings.Join(quoted, "|") + `)(?:$|[^\p{L}\p{N}])`)
	}
	return patterns
}()

// fraudAnalysis is what the text of a mail asks for.
type fraudAnalysis struct {
	// Cues are the phrases found, by cue.
	Cues map[string][]string
	// IBANs are the valid IBANs written in the mail.
	IBANs []string
	// Length is the number of characters of the text.
	Length int
	// ImageOnly is set when the mail shows an image instead of a text.
	ImageOnly bool
}

func (f fraudAnalysis) has(cue string) bool {
	return len(f.Cues[cue]) > 0
}

// found returns the phrases found for the cues, for the details.
func (f fraudAnalysis) found(cues ...string) string {
	var parts []string
	for _, cue := range cues {
		if phrases := f.Cues[cue]; len(phrases) > 0 {
			parts = append(parts, cue+" : « "+strings.Join(phrases, " », « ")+" »")
		}
	}
	return strings.Join(parts, " · ")
}

// CueList lists the cues found, for the detailed view.
func (f fraudAnalysis) CueList() []string {
	var list []string
	for _, cue := range []string{cueBankChange, cuePayment, cueGiftCards, cueSecrecy, cueAvailability, cueUrgency, cueCredentials, cueThreat, cueScan} {
		if f.has(cue) {
			list = append(list, f.found(cue))
		}
	}
	return list
}

// analyzeText looks for the cues of fraud in the subject and the text of a
// mail.
func analyzeText(subject, text string) fraudAnalysis {
	f := fraudAnalysis{Cues: map[string][]string{}, IBANs: findIBANs(text), Length: len(text)}
	normalized := normalizeText(subject + "\n" + text)
	for cue, pattern := range cuePatterns {
		for _, m := range pattern.FindAllStringSubmatch(normalized, -1) {
			if !slices.Contains(f.Cues[cue], m[1]) && len(f.Cues[cue]) < 5 {
				f.Cues[cue] = append(f.Cues[cue], m[1])
			}
		}
	}
	return f
}

// normalizeText lowercases a text, removes the accents and unifies the
// apostrophes and spaces.
func normalizeText(s string) string {
	var b strings.Builder
	space := false
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		switch {
		case unicode.Is(unicode.Mn, r):
		case r == '’' || r == 'ʼ' || r == '`':
			b.WriteByte('\'')
			space = false
		case unicode.IsSpace(r):
			if !space {
				b.WriteByte(' ')
			}
			space = true
		default:
			b.WriteRune(r)
			space = false
		}
	}
	return b.String()
}

// mailText returns the text a reader sees: the HTML part without its
// markup, or the plain text part.
func mailText(mail mailtoolkit.Mail) string {
	var plain, rich string
	for _, key := range contentKeys(mail.Contents) {
		content := mail.Contents[key]
		ct := content.ContentInfo.Type
		if ct.Type != "text" || (ct.Subtype != "html" && ct.Subtype != "plain") {
			continue
		}
		data, err := content.Decode()
		if err != nil {
			continue
		}
		data = toUTF8(data, ct.Parameters["charset"])
		if ct.Subtype == "html" && rich == "" {
			rich = htmlText(data)
		} else if ct.Subtype == "plain" && plain == "" {
			plain = string(data)
		}
	}
	if strings.TrimSpace(rich) != "" {
		return rich
	}
	return plain
}

// htmlText returns the visible text of an HTML document.
func htmlText(data []byte) string {
	z := html.NewTokenizer(bytes.NewReader(data))
	var b strings.Builder
	skip := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			return b.String()
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
			}
		case html.StartTagToken:
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.Style, atom.Script, atom.Head, atom.Title:
				skip++
			case atom.Br, atom.P, atom.Div, atom.Tr, atom.Li, atom.Td, atom.H1, atom.H2, atom.H3:
				b.WriteByte('\n')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.Style, atom.Script, atom.Head, atom.Title:
				skip = max(0, skip-1)
			}
		case html.SelfClosingTagToken:
			b.WriteByte(' ')
		}
	}
}

// externalBanners are the warnings mail gateways add on top of external
// mails; they are not the sender's text.
var externalBanners = regexp.MustCompile(`(?i)[^.\n]*(originated from outside|provient de l'ext[ée]rieur|von ausserhalb|von au[sß]erhalb|external (e-?mail|sender)|courriel externe|exp[ée]diteur externe|externe[rn]? absender|proviene dall'esterno)[^\n]*`)

// imageOnly reports whether the HTML part of a mail is a picture with
// (almost) no text: the message cannot be read by the filters.
func imageOnly(mail mailtoolkit.Mail) bool {
	for _, key := range contentKeys(mail.Contents) {
		content := mail.Contents[key]
		ct := content.ContentInfo.Type
		if ct.Type != "text" || ct.Subtype != "html" {
			continue
		}
		data, err := content.Decode()
		if err != nil {
			return false
		}
		images := 0
		z := html.NewTokenizer(bytes.NewReader(data))
		for t := z.Next(); t != html.ErrorToken; t = z.Next() {
			if t != html.StartTagToken && t != html.SelfClosingTagToken {
				continue
			}
			if token := z.Token(); token.DataAtom == atom.Img {
				attrs := attributes(token)
				if attrs["width"] != "1" && attrs["height"] != "1" && attrs["width"] != "0" && attrs["height"] != "0" {
					images++
				}
			}
		}
		text := externalBanners.ReplaceAllString(htmlText(toUTF8(data, ct.Parameters["charset"])), "")
		return images > 0 && len(strings.Join(strings.Fields(text), " ")) < 40
	}
	return false
}

// freemailDomains are the free mailboxes used by fraudsters posing as an
// executive or a supplier.
var freemailDomains = []string{
	"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.fr", "live.com", "msn.com", "yahoo.com", "yahoo.fr",
	"icloud.com", "me.com", "aol.com", "gmx.ch", "gmx.net", "gmx.de", "gmx.fr", "web.de", "bluewin.ch", "proton.me",
	"protonmail.com", "protonmail.ch", "mail.com", "zoho.com", "yandex.com", "orange.fr", "free.fr", "laposte.net",
	"hispeed.ch", "sunrise.ch", "libero.it",
}

func freemail(domain string) bool {
	return slices.Contains(freemailDomains, strings.ToLower(domain))
}

// assessFraud reports the requests typical of payment fraud (CEO fraud,
// supplier bank details change, gift cards) and of credential phishing.
func assessFraud(r *riskReport, f fraudAnalysis, a *headerAnalysis, add func(level string, weight int, anchor, simple, detail string)) {
	external := a == nil || freemail(a.FromDomain)
	money := f.has(cuePayment) || f.has(cueBankChange) || f.has(cueGiftCards)
	switch {
	case f.has(cueBankChange):
		add(levelDanger, 3, "fraud", "Le message annonce un changement de coordonnées bancaires : c'est la fraude la plus coûteuse pour les entreprises. "+
			"Vérifiez par téléphone, à un numéro que vous connaissez déjà, avant tout paiement.", f.found(cueBankChange, cuePayment))
	case f.has(cueGiftCards) && (f.has(cueUrgency) || f.has(cueSecrecy) || f.has(cueAvailability)):
		add(levelDanger, 3, "fraud", "Le message demande d'acheter des cartes cadeaux dans l'urgence ou en secret : aucune entreprise ni aucun "+
			"supérieur ne paie ainsi, c'est une escroquerie.", f.found(cueGiftCards, cueUrgency, cueSecrecy, cueAvailability))
	case f.has(cuePayment) && (f.has(cueSecrecy) || f.has(cueAvailability)):
		add(levelDanger, 3, "fraud", "Le message demande un paiement en insistant sur la discrétion ou en évitant le téléphone : c'est le "+
			"scénario de la « fraude au président ».", f.found(cuePayment, cueSecrecy, cueAvailability, cueUrgency))
	case f.has(cuePayment) && f.has(cueUrgency):
		weight := 1
		if external || !r.Authenticated {
			weight = 2
		}
		add(levelWarning, weight, "fraud", "Le message demande un paiement urgent : vérifiez la demande par un autre moyen avant de payer.",
			f.found(cuePayment, cueUrgency))
	case f.has(cueAvailability) && f.Length < 600:
		add(levelWarning, 1, "fraud", "Le message, très court, demande si vous êtes disponible : c'est souvent le premier message d'une fraude "+
			"au président, la demande d'argent suivant votre réponse.", f.found(cueAvailability))
	}
	if money && external && a != nil {
		add(levelWarning, 1, "fraud", fmt.Sprintf("Une demande d'argent venant d'une messagerie gratuite (%s) : une entreprise utilise "+
			"son propre domaine.", a.FromDomain), a.FromAddress)
	}
	if f.ImageOnly {
		add(levelWarning, 1, "fraud", "Le message se résume à une image, sans texte : c'est un moyen d'empêcher les filtres de lire "+
			"son contenu.", "aucun texte hors de l'avertissement ajouté par la messagerie")
	}
	if f.has(cueCredentials) && (f.has(cueThreat) || f.has(cueUrgency)) {
		add(levelWarning, 2, "fraud", "Le message réclame vos identifiants en vous mettant sous pression (compte bloqué, délai) : un service "+
			"sérieux ne demande jamais votre mot de passe par mail.", f.found(cueCredentials, cueThreat, cueUrgency))
	}
}

// assessImpersonation reports a display name usurping an executive or the
// organization while the address is outside its domains.
func assessImpersonation(r *riskReport, a *headerAnalysis, trusted, protected []string, add func(level string, weight int, anchor, simple, detail string)) {
	if a == nil || a.FromName == "" {
		return
	}
	name := normalizeText(a.FromName)
	inside := trustedDomain(a.FromDomain, trusted) != ""
	for _, p := range protected {
		if !sameName(name, normalizeText(p)) {
			continue
		}
		switch {
		case !inside:
			add(levelDanger, 3, "headers", fmt.Sprintf("Le nom affiché « %s » est celui d'une personne de votre organisation, mais le message "+
				"vient d'une adresse extérieure (%s) : c'est une usurpation d'identité.", a.FromName, a.FromAddress), a.FromName+" <"+a.FromAddress+">")
		case !r.ProviderAuthenticated(a):
			add(levelWarning, 2, "headers", fmt.Sprintf("Le nom affiché « %s » est celui d'une personne de votre organisation, mais votre "+
				"messagerie n'a pas confirmé que le message vient bien de chez vous.", a.FromName), a.FromName+" <"+a.FromAddress+">")
		}
		return
	}
	if inside {
		return
	}
	for _, t := range trusted {
		label, _, _ := strings.Cut(t, ".")
		label = strings.ReplaceAll(label, "-", " ")
		if len(label) >= 4 && (strings.Contains(name, label) || strings.Contains(strings.ReplaceAll(name, " ", ""), strings.ReplaceAll(label, " ", ""))) {
			add(levelWarning, 2, "headers", fmt.Sprintf("Le nom affiché « %s » reprend le nom de votre organisation, mais l'adresse %s est "+
				"extérieure à ses domaines.", a.FromName, a.FromAddress), a.FromName+" <"+a.FromAddress+">")
			return
		}
	}
}

// commonWords are brand labels that are also ordinary words or first
// names ("Booking confirmation", "Ricardo Silva"): not looked for in display
// names.
var commonWords = []string{"booking", "visa", "apple", "ledger", "ricardo", "sunrise", "outlook", "gmail"}

// displayBrand returns the brand a display name claims ("DHL EXPRESS",
// "Microsoft 365 Security"), nil if none.
func displayBrand(name string) *brand {
	normalized := normalizeText(name)
	words := strings.FieldsFunc(normalized, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	compact := strings.Join(words, "")
	for i, b := range brands {
		label := strings.ReplaceAll(b.Label, "-", "")
		if slices.Contains(commonWords, label) {
			continue
		}
		if slices.Contains(words, label) || (len(label) >= 6 && strings.Contains(compact, label)) {
			return &brands[i]
		}
	}
	return nil
}

// assessDisplayBrand reports a display name naming a brand while the
// address belongs to another domain: the most common disguise of phishing,
// which DMARC does not see (the sender's own domain is authenticated).
func assessDisplayBrand(a *headerAnalysis, add func(level string, weight int, anchor, simple, detail string)) {
	if a == nil || a.FromName == "" || a.Relay != nil {
		return
	}
	b := displayBrand(a.FromName)
	if b == nil || official(mailauth.OrgDomain(a.FromDomain), *b) {
		return
	}
	add(levelDanger, 3, "headers", fmt.Sprintf("Le nom affiché « %s » se présente comme %s, mais le message vient de %s, qui n'appartient pas à %s.",
		a.FromName, b.Name, a.FromDomain, b.Name), a.FromName+" <"+a.FromAddress+">")
}

// sameName reports whether a display name holds every word of a person's
// name, in any order ("Dupont Jean", "Jean Dupont (CEO)").
func sameName(display, person string) bool {
	words := strings.FieldsFunc(person, func(r rune) bool { return !unicode.IsLetter(r) })
	if len(words) == 0 {
		return false
	}
	have := strings.FieldsFunc(display, func(r rune) bool { return !unicode.IsLetter(r) })
	for _, w := range words {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}
