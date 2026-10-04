package qrscan

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

const url = "https://login.example-phish.test/mfa?u=victim"

// encode returns a QR code with the given number of pixels per module,
// with or without its quiet zone.
func encode(t *testing.T, text string, size int, quietZone bool) *gozxing.BitMatrix {
	t.Helper()
	hints := map[gozxing.EncodeHintType]any{}
	if !quietZone {
		hints[gozxing.EncodeHintType_MARGIN] = 0
	}
	m, err := qrcode.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, size, size, hints)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func toImage(m *gozxing.BitMatrix, dark, light color.Gray) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, m.GetWidth(), m.GetHeight()))
	for y := range m.GetHeight() {
		for x := range m.GetWidth() {
			if m.Get(x, y) {
				img.SetGray(x, y, dark)
			} else {
				img.SetGray(x, y, light)
			}
		}
	}
	return img
}

func pngOf(t *testing.T, img image.Image) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func jpegOf(t *testing.T, img image.Image) []byte {
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func expect(t *testing.T, codes []Code, text, source string) {
	t.Helper()
	if len(codes) != 1 || codes[0].Text != text || codes[0].Source != source {
		t.Errorf("got %+v, want %q from %q", codes, text, source)
	}
}

func TestImages(t *testing.T) {
	black, white := color.Gray{0}, color.Gray{255}
	tests := map[string][]byte{
		"png":             pngOf(t, toImage(encode(t, url, 300, true), black, white)),
		"jpeg":            jpegOf(t, toImage(encode(t, url, 300, true), black, white)),
		"one pixel":       pngOf(t, toImage(encode(t, url, 1, false), black, white)),
		"no quiet zone":   pngOf(t, toImage(encode(t, url, 200, false), black, white)),
		"inverted":        pngOf(t, toImage(encode(t, url, 300, true), white, black)),
		"transparent bg":  transparent(t, encode(t, url, 250, false)),
		"in a large page": inPage(t, encode(t, url, 180, true)),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			expect(t, NewScanner(5).Image("img", data), url, "img")
		})
	}
}

// transparent draws the dark modules on a transparent background, as
// logos and QR codes exported for the web often are.
func transparent(t *testing.T, m *gozxing.BitMatrix) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, m.GetWidth(), m.GetHeight()))
	for y := range m.GetHeight() {
		for x := range m.GetWidth() {
			if m.Get(x, y) {
				img.Set(x, y, color.NRGBA{20, 20, 60, 255})
			}
		}
	}
	return pngOf(t, img)
}

// inPage places the code in a larger image with text-like noise around.
func inPage(t *testing.T, m *gozxing.BitMatrix) []byte {
	img := image.NewGray(image.Rect(0, 0, 900, 700))
	for i := range img.Pix {
		img.Pix[i] = 245
	}
	for y := 40; y < 600; y += 24 {
		for x := 30; x < 400; x++ {
			if (x/7)%3 != 0 {
				img.Pix[y*img.Stride+x] = 60
			}
		}
	}
	for y := range m.GetHeight() {
		for x := range m.GetWidth() {
			if m.Get(x, y) {
				img.Pix[(400+y)*img.Stride+600+x] = 0
			} else {
				img.Pix[(400+y)*img.Stride+600+x] = 255
			}
		}
	}
	return pngOf(t, img)
}

func TestNoCode(t *testing.T) {
	img := image.NewGray(image.Rect(0, 0, 200, 100))
	for _, data := range [][]byte{pngOf(t, img), []byte("not an image"), nil} {
		if codes := NewScanner(5).Image("x", data); len(codes) != 0 {
			t.Errorf("%+v", codes)
		}
	}
}

func TestBudget(t *testing.T) {
	data := pngOf(t, toImage(encode(t, url, 200, true), color.Gray{0}, color.Gray{255}))
	s := NewScanner(1)
	if len(s.Image("a", data)) != 1 || len(s.Image("b", pngOf(t, toImage(encode(t, "other", 200, true), color.Gray{0}, color.Gray{255})))) != 0 {
		t.Error("budget not enforced")
	}
	// The same code is reported once per mail.
	s = NewScanner(5)
	if len(s.Image("a", data)) != 1 || len(s.Image("b", data)) != 0 {
		t.Error("duplicate reported")
	}
}

func TestOversizedImage(t *testing.T) {
	// A PNG header announcing a huge image is rejected before decoding.
	var b bytes.Buffer
	png.Encode(&b, image.NewGray(image.Rect(0, 0, 1, 1)))
	data := b.Bytes()
	copy(data[16:24], []byte{0, 0, 0x40, 0, 0, 0, 0x40, 0}) // 16384 x 16384
	if codes := NewScanner(5).Image("x", data); codes != nil {
		t.Errorf("%+v", codes)
	}
}

// pdfWith builds a minimal PDF holding one image XObject.
func pdfWith(dict string, stream []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	fmt.Fprintf(&b, "5 0 obj\n<< /Type /XObject /Subtype /Image %s /Length %d >>\nstream\n", dict, len(stream))
	b.Write(stream)
	b.WriteString("\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
	return b.Bytes()
}

func deflate(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func TestPDF(t *testing.T) {
	m := encode(t, url, 1, false) // one sample per module, as generators do
	w, h := m.GetWidth(), m.GetHeight()
	stride := (w + 7) / 8
	mask := make([]byte, stride*h) // 0 = painted
	gray := make([]byte, w*h)
	for y := range h {
		for x := range w {
			if m.Get(x, y) {
				gray[y*w+x] = 0
			} else {
				mask[y*stride+x/8] |= 0x80 >> (x % 8)
				gray[y*w+x] = 255
			}
		}
	}
	// PNG predictor "Up" on the gray image.
	predicted := make([]byte, 0, (w+1)*h)
	for y := range h {
		predicted = append(predicted, 2)
		for x := range w {
			up := byte(0)
			if y > 0 {
				up = gray[(y-1)*w+x]
			}
			predicted = append(predicted, gray[y*w+x]-up)
		}
	}
	big := toImage(encode(t, url, 300, true), color.Gray{0}, color.Gray{255})

	tests := map[string][]byte{
		"stencil mask": pdfWith(fmt.Sprintf("/Width %d /Height %d /ImageMask true /Filter /FlateDecode", w, h), deflate(mask)),
		"gray 8 bits":  pdfWith(fmt.Sprintf("/Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter [/FlateDecode]", w, h), deflate(gray)),
		"predictor": pdfWith(fmt.Sprintf("/Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode "+
			"/DecodeParms << /Predictor 12 /Columns %d >>", w, h, w), deflate(predicted)),
		"jpeg": pdfWith("/Width 300 /Height 300 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode", jpegOf(t, big)),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			expect(t, NewScanner(5).File("invoice.pdf", data), url, "invoice.pdf (image 1)")
		})
	}
	// Inverted with /Decode [1 0].
	inverted := make([]byte, len(gray))
	for i, v := range gray {
		inverted[i] = 255 - v
	}
	data := pdfWith(fmt.Sprintf("/Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Decode [1 0] /Filter /FlateDecode", w, h), deflate(inverted))
	expect(t, NewScanner(5).File("x.pdf", data), url, "x.pdf (image 1)")
}

func TestOffice(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, _ := z.Create("word/document.xml")
	f.Write([]byte("<w:document/>"))
	f, _ = z.Create("word/media/image1.png")
	f.Write(pngOf(t, toImage(encode(t, url, 250, true), color.Gray{0}, color.Gray{255})))
	z.Close()
	expect(t, NewScanner(5).File("facture.docx", b.Bytes()), url, "facture.docx (image1.png)")
}

func TestImplausibleSkipped(t *testing.T) {
	s := NewScanner(1)
	for _, size := range [][2]int{{1, 1}, {1200, 60}, {10, 300}} {
		s.Image("x", pngOf(t, image.NewGray(image.Rect(0, 0, size[0], size[1]))))
	}
	data := pngOf(t, toImage(encode(t, url, 200, true), color.Gray{0}, color.Gray{255}))
	if len(s.Image("qr", data)) != 1 || s.Skipped != 0 {
		t.Error("pixel or banner counted in the budget")
	}
	if s.Image("again", pngOf(t, toImage(encode(t, "other", 200, true), color.Gray{0}, color.Gray{255}))); s.Skipped != 1 {
		t.Errorf("skipped %d", s.Skipped)
	}
}
