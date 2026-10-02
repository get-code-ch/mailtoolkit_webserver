package filecheck

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/get-code-ch/mailtoolkit_webserver/cfb"
)

const (
	maxEntries = 50
	// maxXMLPart bounds the decompressed size of an inspected archive part.
	maxXMLPart = 4 << 20
)

func isCFB(data []byte) bool { return cfb.IsCFB(data) }

// inspectOLE inspects an Office 97-2003 compound file.
func inspectOLE(r *Report, data []byte) {
	f, err := cfb.Open(data)
	if err != nil {
		r.alert(LevelWarning, "Document Office endommagé ou volontairement malformé : il n'a pas pu être inspecté")
		return
	}
	var vba, embedded, outlook bool
	for _, e := range f.Entries() {
		name := strings.ToLower(e.Name)
		switch {
		case strings.HasPrefix(name, "__substg1.0_"):
			outlook = true
		case e.Type == cfb.TypeStorage && (name == "vba" || name == "_vba_project_cur" || name == "macros"):
			vba = true
		case name == "\x01ole10native" || name == "\x01ole" || name == "package":
			embedded = true
		}
	}
	switch {
	case outlook:
		r.family, r.Kind = familyOutlook, "Message Outlook (.msg)"
	case has(f, "WordDocument"):
		r.Kind = "Document Word 97-2003"
	case has(f, "Workbook") || has(f, "Book"):
		r.Kind = "Classeur Excel 97-2003"
		inspectWorkbook(r, f)
	case has(f, "PowerPoint Document"):
		r.Kind = "Présentation PowerPoint 97-2003"
	case has(f, "EncryptedPackage"):
		r.family, r.Kind = familyEncrypted, "Document Office chiffré"
		r.alert(LevelWarning, "Document protégé par mot de passe : son contenu ne peut pas être analysé, technique utilisée pour échapper aux antivirus")
	case has(f, "PROJECT") && has(f, "VBA/dir"):
		r.Kind = "Projet de macros VBA"
	}
	if vba || has(f, "VBA/dir") {
		r.alert(LevelDanger, "Contient des macros VBA : du code s'exécute si vous activez les macros")
	}
	if embedded {
		r.alert(LevelWarning, "Contient un objet embarqué (OLE) : il peut cacher un fichier exécutable")
	}
}

func has(f *cfb.File, path string) bool {
	_, ok := f.Find(path)
	return ok
}

// inspectWorkbook looks for Excel 4.0 (XLM) macro sheets, run without the
// VBA warnings, and very hidden sheets, in the BIFF8 BoundSheet8 records.
func inspectWorkbook(r *Report, f *cfb.File) {
	entry, ok := f.Find("Workbook")
	if !ok {
		entry, ok = f.Find("Book")
	}
	if !ok {
		return
	}
	stream, err := f.ReadStream(entry)
	if err != nil {
		return
	}
	var macroSheet, veryHidden bool
	for offset := 0; offset+4 <= len(stream); {
		recordType := binary.LittleEndian.Uint16(stream[offset:])
		length := int(binary.LittleEndian.Uint16(stream[offset+2:]))
		body := stream[offset+4 : min(offset+4+length, len(stream))]
		if recordType == 0x0085 && len(body) >= 6 { // BoundSheet8
			hidden, sheetType := body[4]&0x03, body[5]
			macroSheet = macroSheet || sheetType == 0x01
			veryHidden = veryHidden || hidden == 0x02
		}
		if recordType == 0x000A && offset > 0 { // EOF of the globals substream
			break
		}
		offset += 4 + length
	}
	if macroSheet {
		r.alert(LevelDanger, "Contient une feuille de macros Excel 4.0 (XLM) : du code s'exécute à l'ouverture si les macros sont activées")
	}
	if veryHidden {
		r.alert(LevelWarning, "Contient une feuille « très masquée », invisible depuis Excel")
	}
}

// inspectZIP inspects a ZIP archive, and the Office and OpenDocument files
// built on it.
func inspectZIP(r *Report, data []byte) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		r.alert(LevelWarning, "Archive ZIP endommagée : son contenu n'a pas pu être inspecté")
		return
	}
	files := map[string]*zip.File{}
	for _, f := range z.File {
		files[f.Name] = f
	}

	switch {
	case files["[Content_Types].xml"] != nil:
		inspectOOXML(r, z)
	case files["mimetype"] != nil && strings.HasPrefix(readPart(files["mimetype"]), "application/vnd.oasis.opendocument"):
		r.family, r.Kind = familyODF, "Document OpenDocument"
		for _, f := range z.File {
			if strings.HasPrefix(f.Name, "Basic/") && !strings.HasSuffix(f.Name, "/") {
				r.alert(LevelDanger, "Contient des macros (LibreOffice Basic)")
				break
			}
		}
	case files["META-INF/MANIFEST.MF"] != nil && hasSuffix(z, ".class"):
		r.family, r.Kind = familyExecutable, "Programme Java (.jar)"
		r.alert(LevelDanger, "Programme Java exécutable")
	default:
		inspectArchive(r, z)
	}
}

func hasSuffix(z *zip.Reader, suffix string) bool {
	for _, f := range z.File {
		if strings.HasSuffix(strings.ToLower(f.Name), suffix) {
			return true
		}
	}
	return false
}

// inspectArchive lists a plain ZIP archive.
func inspectArchive(r *Report, z *zip.Reader) {
	var encrypted, nested bool
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if len(r.Entries) < maxEntries {
			r.Entries = append(r.Entries, f.Name)
		}
		encrypted = encrypted || f.Flags&0x1 != 0
		ext := extensionOf(f.Name)
		switch {
		case dangerousExtensions[ext]:
			r.alert(LevelDanger, "L'archive contient « %s » : ce type de fichier peut exécuter du code", f.Name)
		case macroExtensions[ext]:
			r.alert(LevelWarning, "L'archive contient « %s », un document pouvant contenir des macros", f.Name)
		case ext == "zip" || ext == "rar" || ext == "7z" || ext == "gz":
			nested = true
		}
	}
	if len(z.File) > maxEntries {
		r.Entries = append(r.Entries, "…")
	}
	if encrypted {
		r.alert(LevelWarning, "Archive protégée par mot de passe : son contenu ne peut pas être analysé, technique utilisée pour échapper aux antivirus")
	}
	if nested {
		r.alert(LevelInfo, "L'archive contient d'autres archives, qui ne sont pas inspectées")
	}
}

type relationships struct {
	Relationships []struct {
		Type       string `xml:"Type,attr"`
		Target     string `xml:"Target,attr"`
		TargetMode string `xml:"TargetMode,attr"`
	} `xml:"Relationship"`
}

// inspectOOXML inspects a Word, Excel or PowerPoint 2007+ document.
func inspectOOXML(r *Report, z *zip.Reader) {
	r.family, r.Kind = familyOOXML, "Document Office"
	var macros, xlm, embedded, activeX bool
	for _, f := range z.File {
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasPrefix(name, "word/"):
			r.Kind = "Document Word"
		case strings.HasPrefix(name, "xl/"):
			r.Kind = "Classeur Excel"
		case strings.HasPrefix(name, "ppt/"):
			r.Kind = "Présentation PowerPoint"
		}
		switch {
		case path.Base(name) == "vbaproject.bin":
			macros = true
		case strings.HasPrefix(name, "xl/macrosheets/"):
			xlm = true
		case strings.Contains(name, "/embeddings/"):
			embedded = true
		case strings.Contains(name, "/activex/"):
			activeX = true
		}
	}
	if macros {
		r.alert(LevelDanger, "Contient des macros VBA : du code s'exécute si vous activez les macros")
	}
	if xlm {
		r.alert(LevelDanger, "Contient une feuille de macros Excel 4.0 (XLM) : du code s'exécute à l'ouverture si les macros sont activées")
	}
	if embedded {
		r.alert(LevelWarning, "Contient un objet embarqué (OLE) : il peut cacher un fichier exécutable")
	}
	if activeX {
		r.alert(LevelWarning, "Contient des contrôles ActiveX, qui peuvent exécuter du code")
	}

	for _, f := range z.File {
		switch {
		case strings.HasSuffix(f.Name, ".rels"):
			var rels relationships
			if xml.Unmarshal([]byte(readPart(f)), &rels) != nil {
				continue
			}
			for _, rel := range rels.Relationships {
				if !strings.EqualFold(rel.TargetMode, "External") {
					continue
				}
				switch kind := path.Base(rel.Type); kind {
				case "hyperlink":
					// Ordinary links, listed by the links panel when displayed.
				case "attachedTemplate", "oleObject", "frame", "subDocument":
					r.alert(LevelDanger, "Charge à l'ouverture un élément distant (%s) : %s", kind, rel.Target)
				default:
					r.alert(LevelWarning, "Référence une ressource externe (%s) : %s", kind, rel.Target)
				}
			}
		case f.Name == "word/document.xml":
			// Dynamic Data Exchange fields run commands when updated.
			if document := strings.ToUpper(readPart(f)); strings.Contains(document, "DDEAUTO") || strings.Contains(document, " DDE ") {
				r.alert(LevelDanger, "Contient un champ DDE : il peut lancer une commande à l'ouverture")
			}
		}
	}
}

// readPart decompresses an archive part, up to maxXMLPart bytes.
func readPart(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	data, _ := io.ReadAll(io.LimitReader(rc, maxXMLPart))
	return string(data)
}
