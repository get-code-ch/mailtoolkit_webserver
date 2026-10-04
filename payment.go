package main

import (
	"math/big"
	"regexp"
	"slices"
	"strings"
)

// payment is a payment order found in a QR code (Swiss QR-bill, SEPA EPC
// code) or an IBAN written in the mail.
type payment struct {
	// Kind is "facture QR", "virement SEPA (EPC)" or "IBAN".
	Kind     string
	IBAN     string
	Valid    bool
	Creditor string
	Country  string
	Amount   string
	Currency string
	// Reference and Message are the remittance information.
	Reference string
	Message   string
	// Problems explain why the order is doubtful.
	Problems []string
}

// Level is the alert level of the payment order.
func (p payment) Level() string {
	if len(p.Problems) > 0 {
		return levelWarning
	}
	return levelInfo
}

// IBANCountry is the country code of the IBAN.
func (p payment) IBANCountry() string {
	if len(p.IBAN) < 2 {
		return ""
	}
	return p.IBAN[:2]
}

// FormattedIBAN groups the IBAN by four characters.
func (p payment) FormattedIBAN() string {
	var b strings.Builder
	for i, c := range p.IBAN {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// ibanLengths are the IBAN lengths of the countries mails usually involve;
// other countries are checked by the checksum only.
var ibanLengths = map[string]int{
	"CH": 21, "LI": 21, "DE": 22, "FR": 27, "IT": 27, "AT": 20, "BE": 16, "NL": 18, "LU": 20, "ES": 24,
	"PT": 25, "GB": 22, "IE": 22, "PL": 28, "CZ": 24, "SK": 24, "HU": 28, "RO": 24, "BG": 22, "HR": 21,
	"SI": 19, "LT": 20, "LV": 21, "EE": 20, "FI": 18, "SE": 24, "DK": 18, "NO": 15, "GR": 27, "CY": 28,
	"MT": 31, "MC": 27, "SM": 27, "TR": 26, "UA": 29, "AE": 23,
}

// normalizeIBAN removes the spaces and uppercases an IBAN.
func normalizeIBAN(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), ""))
}

// validIBAN checks the length of the country and the ISO 7064 checksum.
func validIBAN(iban string) bool {
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	if n, ok := ibanLengths[iban[:2]]; ok && n != len(iban) {
		return false
	}
	var digits strings.Builder
	for _, c := range iban[4:] + iban[:4] {
		switch {
		case c >= '0' && c <= '9':
			digits.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			digits.WriteString(big.NewInt(int64(c - 'A' + 10)).String())
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(digits.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

// qrIBAN reports a Swiss QR-IBAN (institution identifier 30000-31999), only
// valid with a QR reference.
func qrIBAN(iban string) bool {
	if len(iban) != 21 || (iban[:2] != "CH" && iban[:2] != "LI") {
		return false
	}
	return iban[4:6] == "30" || iban[4:6] == "31"
}

// ibanInText finds the IBANs written in a text, grouped by four or not.
var ibanInText = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`)

// findIBANs returns the valid IBANs of a text, once each.
func findIBANs(text string) []string {
	var found []string
	for _, m := range ibanInText.FindAllString(text, -1) {
		iban := normalizeIBAN(m)
		// A grouped match may run into the next word: shorten to the
		// length of the country.
		if n, ok := ibanLengths[iban[:2]]; ok && len(iban) > n {
			iban = iban[:n]
		}
		if validIBAN(iban) && !slices.Contains(found, iban) {
			found = append(found, iban)
		}
	}
	return found
}

// parsePayment reads a Swiss QR-bill (SPC) or a SEPA credit transfer code
// (EPC069-12, "BCD"), false for other contents.
func parsePayment(text string) (payment, bool) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	line := func(i int) string {
		if i < len(lines) {
			return strings.TrimSpace(lines[i])
		}
		return ""
	}
	var p payment
	switch {
	case line(0) == "SPC" && len(lines) >= 28:
		// Swiss Payment Standards, QR-bill: IBAN, creditor (address
		// type, name, 2 address lines, postcode, town, country), ultimate
		// creditor (7 empty lines), amount, currency, ultimate debtor (7),
		// reference type, reference, message.
		p = payment{Kind: "facture QR", IBAN: normalizeIBAN(line(3)), Creditor: line(5), Country: line(10),
			Amount: line(18), Currency: line(19), Reference: line(28), Message: line(29)}
		switch {
		case p.IBANCountry() != "CH" && p.IBANCountry() != "LI":
			p.Problems = append(p.Problems, "une facture QR doit être payée sur un compte suisse ou liechtensteinois, pas "+p.IBANCountry())
		case qrIBAN(p.IBAN) && line(27) != "QRR":
			p.Problems = append(p.Problems, "QR-IBAN sans référence QR : la banque refusera ce paiement")
		}
		if p.Country != "" && p.Country != "CH" && p.Country != "LI" {
			p.Problems = append(p.Problems, "bénéficiaire domicilié hors de Suisse ("+p.Country+")")
		}
	case line(0) == "BCD" && len(lines) >= 7:
		// EPC QR code: version, encoding, SCT, BIC, name, IBAN, amount
		// (EUR12.34), purpose, reference, text.
		p = payment{Kind: "virement SEPA (EPC)", Creditor: line(5), IBAN: normalizeIBAN(line(6)), Reference: line(9), Message: line(10)}
		if amount := line(7); len(amount) > 3 {
			p.Currency, p.Amount = amount[:3], amount[3:]
		}
	default:
		return payment{}, false
	}
	p.Valid = validIBAN(p.IBAN)
	if !p.Valid {
		p.Problems = append([]string{"IBAN invalide (somme de contrôle fausse) : le code a été modifié ou fabriqué"}, p.Problems...)
	}
	return p, true
}
