package main

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/qrscan"
)

// maxQRImages bounds the images scanned for QR codes in one mail.
const maxQRImages = 30

// qrCode is a QR code found in a mail and what it holds.
type qrCode struct {
	qrscan.Code
	// Kind is "lien", "paiement", "Wi-Fi", "contact" or "texte".
	Kind string
	// Link is the analysis of the URL of a "lien" code.
	Link *Link
	// Payment is the payment order of a "paiement" code.
	Payment *payment
}

// Level is the alert level of the code.
func (q qrCode) Level() string {
	switch {
	case q.Link != nil:
		if l := q.Link.Level(); l == levelDanger || l == levelWarning {
			return l
		}
		return levelWarning
	case q.Payment != nil:
		return q.Payment.Level()
	}
	return levelInfo
}

var dataImage = regexp.MustCompile(`(?i)data:image/(?:png|jpe?g|gif|webp|bmp);base64,([A-Za-z0-9+/=\s]+)`)

// qrScan is the result of the scan of a mail.
type qrScan struct {
	Codes []qrCode
	// Skipped counts the images not scanned (too many, or too long).
	Skipped int
}

// findQRCodes scans the images of a mail: inline images, images embedded
// in the HTML (data: URLs), attachments (images, PDF, Office documents).
func findQRCodes(mail mailtoolkit.Mail) qrScan {
	scanner := qrscan.NewScanner(maxQRImages)
	var codes []qrscan.Code
	for _, key := range contentKeys(mail.Contents) {
		content := mail.Contents[key]
		ct := content.ContentInfo.Type
		data, err := content.Decode()
		if err != nil {
			continue
		}
		switch {
		case ct.Type == "image":
			codes = append(codes, scanner.Image("image intégrée "+imageName(content.ContentInfo, key), data)...)
		case ct.Type == "text" && ct.Subtype == "html":
			for i, m := range dataImage.FindAllSubmatch(data, maxQRImages) {
				clean := strings.Join(strings.Fields(string(m[1])), "")
				if img, err := base64.StdEncoding.DecodeString(clean); err == nil {
					codes = append(codes, scanner.Image(fmt.Sprintf("image %d du texte HTML", i+1), img)...)
				}
			}
		}
	}
	for _, name := range sortedKeys(mail.Attachments) {
		if data, err := mail.Attachments[name].Decode(); err == nil {
			codes = append(codes, scanner.File(name, data)...)
		}
	}

	result := qrScan{Skipped: scanner.Skipped}
	for _, c := range codes {
		result.Codes = append(result.Codes, classifyQR(c))
	}
	return result
}

func imageName(info mailtoolkit.ContentInfo, key string) string {
	for _, name := range []string{info.Disposition.Parameters["filename"], info.Type.Parameters["name"]} {
		if name != "" {
			return name
		}
	}
	return key
}

// classifyQR tells what a QR code holds.
func classifyQR(c qrscan.Code) qrCode {
	q := qrCode{Code: c, Kind: "texte"}
	text := strings.TrimSpace(c.Text)
	lower := strings.ToLower(text)
	switch {
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "www."):
		raw := text
		if strings.HasPrefix(lower, "www.") {
			raw = "http://" + text
		}
		link := analyzeLink(cleanURL(raw), "", "QR code", c.Source)
		link.Warnings = append(link.Warnings, LinkWarning{levelInfo,
			"Lien caché dans un QR code : il s'ouvre sur un téléphone, hors des protections de l'ordinateur et du filtre de la messagerie"})
		q.Kind, q.Link = "lien", &link
	case strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "smsto:") || strings.HasPrefix(lower, "tel:"):
		q.Kind = "contact"
	case strings.HasPrefix(lower, "wifi:"):
		q.Kind = "Wi-Fi"
	case strings.HasPrefix(text, "BEGIN:VCARD"):
		q.Kind = "contact"
	default:
		if p, ok := parsePayment(text); ok {
			q.Kind, q.Payment = "paiement", &p
		}
	}
	return q
}

// qrLinks returns the links of the QR codes, for the links panel and the
// reputation checks.
func qrLinks(codes []qrCode) []Link {
	var links []Link
	for _, c := range codes {
		if c.Link != nil {
			links = append(links, *c.Link)
		}
	}
	return links
}

// attachmentLinks returns the links of the attached documents, analyzed
// like the links of the mail.
func attachmentLinks(attachments []attachmentView) []Link {
	var links []Link
	for _, a := range attachments {
		for _, raw := range a.Links {
			links = append(links, analyzeLink(cleanURL(raw), "", "pièce jointe", a.Name))
		}
	}
	return links
}

// assessQR reports the QR codes: a link hidden in a QR code escapes the
// mail filters, and a request to scan one to log in is the quishing
// scenario.
func assessQR(r *riskReport, codes []qrCode, f fraudAnalysis, add func(level string, weight int, anchor, simple, detail string)) {
	for _, c := range codes {
		switch {
		case c.Link != nil && !r.Trusted && (f.has(cueCredentials) || f.has(cueThreat)):
			add(levelDanger, 3, "qrcodes", "Le message vous demande de scanner un QR code pour vous connecter ou débloquer un compte : c'est "+
				"l'hameçonnage par QR code (« quishing »), conçu pour échapper aux protections de l'ordinateur.",
				c.Link.URL+" ("+c.Source+") · "+f.found(cueCredentials, cueThreat, cueScan))
		case c.Link != nil && !r.Trusted:
			add(levelWarning, 1, "qrcodes", "Le message contient un QR code qui mène vers "+c.Link.Host+" : son lien échappe au filtre de "+
				"la messagerie. Ne le scannez que si vous attendiez ce message.", c.Link.URL+" ("+c.Source+")")
		case c.Payment != nil && len(c.Payment.Problems) > 0:
			add(levelWarning, 2, "qrcodes", "Le message contient un ordre de paiement ("+c.Payment.Kind+") douteux : "+c.Payment.Problems[0]+".",
				c.Payment.FormattedIBAN()+" "+c.Payment.Creditor)
		case c.Payment != nil:
			add(levelInfo, 0, "qrcodes", fmt.Sprintf("Le message contient un ordre de paiement (%s) pour %s, sur le compte %s : vérifiez que "+
				"ce compte est bien celui du fournisseur avant de payer.", c.Payment.Kind, orDefault(c.Payment.Creditor, "un bénéficiaire non indiqué"),
				c.Payment.FormattedIBAN()), "")
		}
	}
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
