// Package filecheck inspects a mail attachment without opening it: real
// type from its content, hashes, and the features used to deliver malware
// or phishing (macros, executables, embedded objects, scripts...).
package filecheck

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
)

// Alert levels, from the most to the least severe.
const (
	LevelDanger  = "danger"
	LevelWarning = "warning"
	LevelInfo    = "info"
)

type Alert struct {
	Level   string
	Message string
}

// Report is the analysis of one file.
type Report struct {
	Name         string
	Size         int
	MD5          string
	SHA1         string
	SHA256       string
	DeclaredType string
	// Kind describes the type detected from the content.
	Kind   string
	Alerts []Alert
	// Entries lists the content of an archive (first maxEntries).
	Entries []string
	family  string
}

// Level returns the most severe alert level, "" if none.
func (r Report) Level() string {
	level := ""
	for _, a := range r.Alerts {
		switch {
		case a.Level == LevelDanger:
			return LevelDanger
		case a.Level == LevelWarning:
			level = LevelWarning
		case level == "":
			level = LevelInfo
		}
	}
	return level
}

func (r *Report) alert(level, format string, args ...any) {
	r.Alerts = append(r.Alerts, Alert{level, fmt.Sprintf(format, args...)})
}

// Families of detected content.
const (
	familyExecutable = "executable"
	familyOLE        = "office-ole"
	familyOOXML      = "office-ooxml"
	// familyEncrypted is a password protected Office document, stored in a
	// compound file whatever its format.
	familyEncrypted = "office-encrypted"
	familyODF       = "opendocument"
	familyPDF       = "pdf"
	familyRTF       = "rtf"
	familyHTML      = "html"
	familySVG       = "svg"
	familyZIP       = "zip"
	familyArchive   = "archive"
	familyDiskImage = "disk-image"
	familyShortcut  = "shortcut"
	familyImage     = "image"
	familyText      = "text"
	familyMail      = "mail"
	familyOutlook   = "outlook"
	familyOther     = "other"
)

// Analyze inspects a file. name and declaredType come from the mail and are
// not trusted.
func Analyze(name, declaredType string, data []byte) Report {
	r := Report{Name: name, Size: len(data), DeclaredType: strings.ToLower(declaredType)}
	md5sum, sha1sum, sha256sum := md5.Sum(data), sha1.Sum(data), sha256.Sum256(data)
	r.MD5, r.SHA1, r.SHA256 = hex.EncodeToString(md5sum[:]), hex.EncodeToString(sha1sum[:]), hex.EncodeToString(sha256sum[:])

	checkName(&r)
	detect(&r, data)
	checkExtension(&r)
	sort.SliceStable(r.Alerts, func(i, j int) bool { return severity(r.Alerts[i].Level) < severity(r.Alerts[j].Level) })
	return r
}

var magics = []struct {
	prefix string
	family string
	kind   string
}{
	{"MZ", familyExecutable, "Exécutable Windows (PE)"},
	{"\x7fELF", familyExecutable, "Exécutable Linux (ELF)"},
	{"\xcf\xfa\xed\xfe", familyExecutable, "Exécutable macOS (Mach-O)"},
	{"\xce\xfa\xed\xfe", familyExecutable, "Exécutable macOS (Mach-O)"},
	{"\xca\xfe\xba\xbe", familyExecutable, "Exécutable macOS universel ou classe Java"},
	{"L\x00\x00\x00\x01\x14\x02\x00", familyShortcut, "Raccourci Windows (.lnk)"},
	{"%PDF", familyPDF, "Document PDF"},
	{"{\\rt", familyRTF, "Document RTF"},
	{"Rar!\x1a\x07", familyArchive, "Archive RAR"},
	{"7z\xbc\xaf\x27\x1c", familyArchive, "Archive 7-Zip"},
	{"\x1f\x8b", familyArchive, "Archive gzip"},
	{"BZh", familyArchive, "Archive bzip2"},
	{"\xfd7zXZ\x00", familyArchive, "Archive xz"},
	{"MSCF", familyArchive, "Archive Cabinet (.cab)"},
	{"\x89PNG\r\n\x1a\n", familyImage, "Image PNG"},
	{"\xff\xd8\xff", familyImage, "Image JPEG"},
	{"GIF87a", familyImage, "Image GIF"},
	{"GIF89a", familyImage, "Image GIF"},
	{"BM", familyImage, "Image BMP"},
	{"II*\x00", familyImage, "Image TIFF"},
	{"MM\x00*", familyImage, "Image TIFF"},
}

func detect(r *Report, data []byte) {
	for _, m := range magics {
		if bytes.HasPrefix(data, []byte(m.prefix)) {
			r.family, r.Kind = m.family, m.kind
			break
		}
	}
	switch {
	case r.family != "":
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		r.family, r.Kind = familyImage, "Image WebP"
	case isCFB(data):
		r.family, r.Kind = familyOLE, "Document Office 97-2003 (OLE)"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")):
		r.family, r.Kind = familyZIP, "Archive ZIP"
	case len(data) > 0x8006 && string(data[0x8001:0x8006]) == "CD001":
		r.family, r.Kind = familyDiskImage, "Image disque ISO"
	default:
		detectText(r, data)
	}

	switch r.family {
	case familyExecutable:
		r.alert(LevelDanger, "Programme exécutable : ne l'ouvrez pas")
	case familyShortcut:
		r.alert(LevelDanger, "Raccourci Windows : peut lancer n'importe quelle commande à l'ouverture")
	case familyDiskImage:
		r.alert(LevelDanger, "Image disque : son contenu échappe aux protections de Windows sur les fichiers téléchargés")
	case familyArchive:
		r.alert(LevelWarning, "Archive dont le contenu n'est pas inspecté : prudence avec les fichiers qu'elle contient")
	case familyOLE:
		inspectOLE(r, data)
	case familyZIP:
		inspectZIP(r, data)
	case familyPDF:
		inspectPDF(r, data)
	case familyRTF:
		inspectRTF(r, data)
	case familyHTML, familySVG:
		inspectHTML(r, data)
	}
}

// detectText recognizes the text formats.
func detectText(r *Report, data []byte) {
	head := bytes.ToLower(data[:min(len(data), 4096)])
	contentType := http.DetectContentType(data)
	switch {
	case bytes.Contains(head, []byte("<svg")):
		r.family, r.Kind = familySVG, "Image vectorielle SVG"
	case strings.HasPrefix(contentType, "text/html") || bytes.Contains(head, []byte("<html")) || bytes.Contains(head, []byte("<script")):
		r.family, r.Kind = familyHTML, "Page HTML"
	case looksLikeMail(head):
		r.family, r.Kind = familyMail, "Message électronique"
	case strings.HasPrefix(contentType, "text/"):
		r.family, r.Kind = familyText, "Texte"
	default:
		r.family, r.Kind = familyOther, "Données ("+contentType+")"
	}
}

func looksLikeMail(head []byte) bool {
	found := 0
	for _, h := range []string{"\nfrom:", "\nsubject:", "\ndate:", "\nmessage-id:", "\nreceived:", "\nmime-version:"} {
		if bytes.Contains(append([]byte("\n"), head...), []byte(h)) {
			found++
		}
	}
	return found >= 2
}

// Extensions which run code when opened on Windows or macOS.
var dangerousExtensions = setOf("exe", "scr", "com", "pif", "cpl", "msi", "msix", "msp", "appx", "appxbundle",
	"bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "hta", "jar", "lnk", "reg",
	"chm", "iso", "img", "vhd", "vhdx", "dll", "ocx", "sys", "xll", "iqy", "slk", "url", "scf", "library-ms",
	"settingcontent-ms", "one", "application", "gadget", "inf", "msc", "sct", "shb", "website", "app", "command",
	"pkg", "dmg", "apk", "sh")

var macroExtensions = setOf("docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppsm", "sldm")

// Extensions people trust, used as decoys before a dangerous one.
var documentExtensions = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png",
	"gif", "zip", "rtf", "odt", "csv", "mp3", "mp4", "html", "htm")

// expectedFamilies maps an extension to the families its content may have.
var expectedFamilies = map[string][]string{
	"pdf": {familyPDF}, "rtf": {familyRTF},
	"doc": {familyOLE}, "xls": {familyOLE}, "ppt": {familyOLE}, "dot": {familyOLE}, "xlt": {familyOLE}, "pps": {familyOLE},
	"docx": {familyOOXML}, "xlsx": {familyOOXML}, "pptx": {familyOOXML}, "docm": {familyOOXML}, "xlsm": {familyOOXML},
	"pptm": {familyOOXML}, "dotx": {familyOOXML}, "xltx": {familyOOXML}, "ppsx": {familyOOXML},
	"odt": {familyODF}, "ods": {familyODF}, "odp": {familyODF},
	"jpg": {familyImage}, "jpeg": {familyImage}, "png": {familyImage}, "gif": {familyImage}, "bmp": {familyImage},
	"webp": {familyImage}, "tif": {familyImage}, "tiff": {familyImage},
	"zip": {familyZIP, familyOOXML, familyODF}, "txt": {familyText, familyMail}, "csv": {familyText},
	"html": {familyHTML}, "htm": {familyHTML}, "svg": {familySVG}, "eml": {familyMail, familyText},
	"msg": {familyOutlook}, "exe": {familyExecutable}, "dll": {familyExecutable},
}

func init() {
	for ext, families := range expectedFamilies {
		if families[0] == familyOLE || families[0] == familyOOXML {
			expectedFamilies[ext] = append(families, familyEncrypted)
		}
	}
}

func setOf(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

func extensionOf(name string) string {
	return strings.ToLower(strings.TrimPrefix(path.Ext(strings.TrimRight(name, ". ")), "."))
}

// checkName looks for names built to hide the real extension.
func checkName(r *Report) {
	for _, c := range r.Name {
		if (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F {
			r.alert(LevelDanger, "Le nom contient un caractère d'inversion du sens d'écriture : l'extension affichée est fausse, la vraie est .%s", extensionOf(r.Name))
			break
		}
	}
	if strings.TrimRight(r.Name, ". ") != r.Name {
		r.alert(LevelWarning, "Le nom se termine par des points ou des espaces, ignorés par Windows")
	}
	ext := extensionOf(r.Name)
	base := strings.TrimSuffix(strings.TrimRight(r.Name, ". "), path.Ext(strings.TrimRight(r.Name, ". ")))
	if inner := extensionOf(strings.TrimRight(base, " ")); documentExtensions[inner] && dangerousExtensions[ext] {
		r.alert(LevelDanger, "Double extension « .%s.%s » : ce n'est pas un document mais un fichier .%s", inner, ext, ext)
	} else if strings.HasSuffix(base, "  ") {
		r.alert(LevelWarning, "Nombreux espaces avant l'extension : souvent utilisé pour la cacher")
	}
}

// checkExtension compares the extension with the detected content.
func checkExtension(r *Report) {
	ext := extensionOf(r.Name)
	switch {
	case dangerousExtensions[ext] && r.family != familyExecutable && r.family != familyShortcut && r.family != familyDiskImage:
		r.alert(LevelDanger, "Extension .%s : ce type de fichier peut exécuter du code à l'ouverture", ext)
	case macroExtensions[ext]:
		r.alert(LevelWarning, "Extension .%s : format prévu pour contenir des macros", ext)
	}

	expected, known := expectedFamilies[ext]
	if !known || r.family == "" {
		return
	}
	for _, family := range expected {
		if family == r.family {
			return
		}
	}
	level := LevelWarning
	switch r.family {
	case familyExecutable, familyShortcut, familyHTML, familyDiskImage, familyRTF:
		// RTF renamed .doc is a classic exploit delivery.
		level = LevelDanger
	}
	r.alert(level, "L'extension .%s ne correspond pas au contenu réel : %s", ext, r.Kind)
}
