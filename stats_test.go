package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func TestStats(t *testing.T) {
	dir := t.TempDir()
	clock := &testClock{time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	s, err := newStatsStore(dir, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	red := riskReport{Light: riskRed, Reasons: []riskReason{{Weight: 3, Anchor: "links"}, {Weight: 1, Anchor: "links"}, {Weight: 0, Anchor: "dmarc"}}}
	lookalikes := []lookalike{{Domain: "paypa1.com", Brand: "PayPal"}}
	s.recordSubmission("mx", 1)
	s.recordSubmission(modeUpload, 1)
	s.recordAnalysis("/inbox/a/1/1", red, lookalikes, reputation{}, []qrCode{{Link: &Link{}}}, []string{"evil.example"})
	s.recordAnalysis("/inbox/a/1/1", red, lookalikes, reputation{}, nil, nil) // displayed again
	clock.now = clock.now.Add(24 * time.Hour)
	s.recordAnalysis("/inbox/b/1/1", riskReport{Light: riskGreen}, nil, reputation{}, nil, nil)

	// Reloaded from the file.
	s, err = newStatsStore(dir, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	p := s.period(7)
	if p.Analyses != 2 || p.Received != 1 || p.Uploaded != 1 || p.Mails != 2 || p.QRCodes != 1 || p.Lights[riskRed] != 1 || p.Percent(riskRed) != 50 {
		t.Errorf("%+v", p)
	}
	if len(p.Reasons) != 1 || p.Reasons[0] != (statsCount{"links", 1, 100}) || p.Brands[0].Key != "PayPal" || p.Domains[0].Key != "paypa1.com" {
		t.Errorf("%+v %+v %+v", p.Reasons, p.Brands, p.Domains)
	}
	if len(p.Daily) != 7 || p.Daily[5].Red != 1 || p.Daily[6].Green != 1 || p.From != "2026-09-26" || p.To != "2026-10-02" {
		t.Errorf("%+v", p.Daily)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, statsFile))
	if strings.Contains(string(raw), "/inbox/") {
		t.Error("mail keys stored in clear")
	}

	// Old days and mails are forgotten.
	clock.now = clock.now.AddDate(0, 0, statsDays+1)
	s.recordSubmission("mx", 0)
	if p := s.period(statsDays); p.Analyses != 0 || len(s.data.Recorded) != 0 || len(s.data.Days) != 1 {
		t.Errorf("not pruned: %d days, %d mails", len(s.data.Days), len(s.data.Recorded))
	}
}

func TestStatsChart(t *testing.T) {
	c := newStatsChart([]statsDay{{Date: "2026-10-01", Green: 2, Red: 2}, {Date: "2026-10-02"}})
	if c.Max != 4 || len(c.Bars) != 2 || len(c.Bars[0].Segments) != 2 || c.Bars[0].Segments[1] != (statsSegment{"bar-red", 0, 80}) {
		t.Errorf("%+v", c)
	}
}

func TestAdmin(t *testing.T) {
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	if get(handler, "/admin").Code != http.StatusNotFound {
		t.Error("admin page without token")
	}

	s.adminToken = strings.Repeat("k", 32)
	s.stats, _ = newStatsStore(t.TempDir(), time.Now)
	s.store.onSubmission = s.stats.recordSubmission
	handler = s.routes(t.TempDir())
	login := func(password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/admin?days=7", nil)
		r.RemoteAddr = "192.0.2.9:1234"
		if password != "" {
			r.SetBasicAuth("admin", password)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	if w := login(""); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("anonymous: %d", w.Code)
	}
	raw, _ := os.ReadFile("testdata/multipart.eml")
	location := postFile(t, handler, "/upload", "x.eml", raw).Header().Get("Location")
	get(handler, location)
	get(handler, location)
	w := login(s.adminToken)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d", w.Code)
	}
	page := w.Body.String()
	for _, want := range []string{"Statistiques", `<span class="tile-value">1</span>`, "<code>upload</code>", `class="active" aria-current="page">7 jours`, "<svg"} {
		if !strings.Contains(page, want) {
			t.Errorf("%q missing", want)
		}
	}

	// Three failures block the address, even with the right token.
	for range 3 {
		if login("wrong").Code != http.StatusUnauthorized {
			t.Error("wrong token accepted")
		}
	}
	if login(s.adminToken).Code != http.StatusTooManyRequests {
		t.Error("not blocked")
	}
}

// qrPNG encodes text as a QR code image.
func qrPNG(t *testing.T, text string) []byte {
	t.Helper()
	m, err := qrcode.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, 240, 240, nil)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewGray(image.Rect(0, 0, m.GetWidth(), m.GetHeight()))
	for y := range m.GetHeight() {
		for x := range m.GetWidth() {
			if !m.Get(x, y) {
				img.SetGray(x, y, color.Gray{255})
			}
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func TestQuishingPage(t *testing.T) {
	image := base64.StdEncoding.EncodeToString(qrPNG(t, "https://mfa-renew.example.net/login"))
	mail := fmt.Sprintf("From: IT Support <it@example.org>\r\nTo: a@example.com\r\nSubject: Action requise\r\nDate: Thu, 1 Oct 2026 10:00:00 +0200\r\n"+
		"Message-ID: <q@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=b\r\n\r\n"+
		"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Votre double authentification expire. Scannez le code QR :</p><img src=\"cid:qr\">\r\n"+
		"--b\r\nContent-Type: image/png\r\nContent-ID: <qr>\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--b--\r\n", image)
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	location := postFile(t, handler, "/upload", "q.eml", []byte(mail)).Header().Get("Location")
	page := get(handler, location).Body.String()
	for _, want := range []string{`id="qrcodes"`, "https://mfa-renew.example.net/login", "quishing", "light-red", `<span class="badge">QR code</span>`, "double authentification"} {
		if !strings.Contains(page, want) {
			t.Errorf("%q missing", want)
		}
	}
}

// TestLureAttachmentPage: a short Word document whose only link leads to a
// SharePoint share, the page behind it asking for the Microsoft 365
// password before showing the malicious link.
func TestLureAttachmentPage(t *testing.T) {
	var doc bytes.Buffer
	z := zip.NewWriter(&doc)
	for name, content := range map[string]string{
		"[Content_Types].xml": `<Types/>`,
		"word/document.xml":   `<w:document><w:body><w:p><w:r><w:t>Un document sécurisé vous a été partagé : Ouvrir</w:t></w:r></w:p></w:body></w:document>`,
		"word/_rels/document.xml.rels": `<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" ` +
			`Target="https://fabrikam-my.sharepoint.com/:b:/g/personal/finance/EabcDEF" TargetMode="External"/></Relationships>`,
	} {
		f, _ := z.Create(name)
		f.Write([]byte(content))
	}
	z.Close()
	mail := "From: Comptabilite <compta@fabrikam.example>\r\nTo: a@example.com\r\nSubject: Paiement en attente\r\nDate: Thu, 1 Oct 2026 10:00:00 +0200\r\n" +
		"Message-ID: <l@fabrikam.example>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBonjour, veuillez trouver le document ci-joint.\r\n" +
		"--b\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n" +
		"Content-Disposition: attachment; filename=\"Avis de paiement.docx\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(doc.Bytes()) + "\r\n--b--\r\n"
	s := newTestServer(t)
	handler := s.routes(t.TempDir())
	location := postFile(t, handler, "/upload", "l.eml", []byte(mail)).Header().Get("Location")
	page := get(handler, location).Body.String()
	for _, want := range []string{"light-red", "Document leurre", "lien vers SharePoint", `<span class="badge">pièce jointe</span>`,
		"fabrikam-my.sharepoint.com"} {
		if !strings.Contains(page, want) {
			t.Errorf("%q missing", want)
		}
	}
}
