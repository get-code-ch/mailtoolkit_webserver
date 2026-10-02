package filecheck

import (
	"bytes"
	"encoding/hex"
	"regexp"
	"strings"
)

var pdfName = regexp.MustCompile(`/[A-Za-z0-9#]+`)

// pdfKeywords are the PDF names that trigger actions or carry content.
var pdfKeywords = []struct {
	name    string
	level   string
	message string
}{
	{"JavaScript", LevelDanger, "Contient du JavaScript"},
	{"JS", LevelDanger, "Contient du JavaScript"},
	{"Launch", LevelDanger, "Peut lancer un programme (action Launch)"},
	{"EmbeddedFile", LevelDanger, "Contient un fichier embarqué"},
	{"RichMedia", LevelWarning, "Contient du contenu multimédia actif (RichMedia)"},
	{"OpenAction", LevelWarning, "Exécute une action automatique à l'ouverture"},
	{"AA", LevelWarning, "Exécute des actions automatiques"},
	{"XFA", LevelWarning, "Contient un formulaire XFA, qui peut embarquer des scripts"},
	{"SubmitForm", LevelWarning, "Peut envoyer les données saisies vers un serveur"},
	{"AcroForm", LevelInfo, "Contient un formulaire"},
	{"Encrypt", LevelInfo, "Document chiffré : son contenu n'est pas inspecté"},
	{"ObjStm", LevelInfo, "Contient des objets compressés, qui ne sont pas inspectés"},
}

// inspectPDF looks for the PDF names that trigger actions. Names can be
// obfuscated with #xx escapes, they are decoded first.
func inspectPDF(r *Report, data []byte) {
	found := map[string]int{}
	for _, match := range pdfName.FindAll(data, -1) {
		found[decodePDFName(string(match[1:]))]++
	}
	seen := map[string]bool{}
	for _, k := range pdfKeywords {
		if found[k.name] > 0 && !seen[k.message] {
			seen[k.message] = true
			r.alert(k.level, "%s", k.message)
		}
	}
	if n := found["URI"]; n > 0 {
		r.alert(LevelInfo, "Contient %d lien%s", n, plural(n))
	}
}

func decodePDFName(name string) string {
	if !strings.Contains(name, "#") {
		return name
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] == '#' && i+2 < len(name) {
			if decoded, err := hex.DecodeString(name[i+1 : i+3]); err == nil {
				b.Write(decoded)
				i += 2
				continue
			}
		}
		b.WriteByte(name[i])
	}
	return b.String()
}

func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}

// inspectRTF looks for embedded OLE objects, the vector of most RTF
// exploits (equation editor, OLE2Link...).
func inspectRTF(r *Report, data []byte) {
	lower := bytes.ToLower(data)
	switch {
	case bytes.Contains(lower, []byte(`\objupdate`)):
		r.alert(LevelDanger, "Contient un objet embarqué mis à jour automatiquement à l'ouverture (technique d'exploitation connue)")
	case bytes.Contains(lower, []byte(`\object`)) || bytes.Contains(lower, []byte(`\objdata`)):
		r.alert(LevelDanger, "Contient un objet embarqué (OLE), vecteur fréquent d'exploitation des documents RTF")
	}
	if bytes.Contains(lower, []byte("equation.3")) {
		r.alert(LevelDanger, "Contient un objet « Equation.3 », exploité par une faille connue de Microsoft Office (CVE-2017-11882)")
	}
}

var htmlPatterns = []struct {
	pattern *regexp.Regexp
	level   string
	message string
}{
	{regexp.MustCompile(`(?i)<script`), LevelDanger, "Contient du JavaScript, exécuté à l'ouverture dans le navigateur"},
	{regexp.MustCompile(`(?i)\son[a-z]+\s*=`), LevelDanger, "Contient du code exécuté sur des événements (onload, onclick...)"},
	{regexp.MustCompile(`(?i)<form|<input[^>]+type\s*=\s*["']?password`), LevelDanger, "Contient un formulaire : typique des fausses pages de connexion"},
	{regexp.MustCompile(`(?i)atob\s*\(|new\s+Blob|msSaveOrOpenBlob|createObjectURL|\.download\s*=`), LevelDanger, "Fabrique un fichier dans le navigateur (HTML smuggling) pour contourner les filtres"},
	{regexp.MustCompile(`(?i)http-equiv\s*=\s*["']?refresh|window\.location|location\.href|location\.replace`), LevelWarning, "Redirige vers un autre site"},
	{regexp.MustCompile(`(?i)<foreignobject|<iframe|<embed|<object`), LevelWarning, "Embarque d'autres contenus"},
	{regexp.MustCompile(`(?i)javascript:`), LevelDanger, "Contient des liens javascript:"},
}

// inspectHTML inspects an HTML page or an SVG image: both open in the
// browser and run their scripts locally.
func inspectHTML(r *Report, data []byte) {
	if r.family == familyHTML {
		r.alert(LevelWarning, "Page web jointe : elle s'ouvre dans le navigateur, hors de la protection de la messagerie")
	}
	seen := map[string]bool{}
	for _, p := range htmlPatterns {
		if !seen[p.message] && p.pattern.Match(data) {
			seen[p.message] = true
			r.alert(p.level, "%s", p.message)
		}
	}
}

func severity(level string) int {
	switch level {
	case LevelDanger:
		return 0
	case LevelWarning:
		return 1
	}
	return 2
}
