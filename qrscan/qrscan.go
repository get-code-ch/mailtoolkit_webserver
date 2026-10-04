// Package qrscan finds the QR codes of a mail: in its images, and in the
// images of its PDF and Office attachments. Phishing mails hide their link
// in a QR code (quishing): no link to analyze for the mail filters, and the
// page opens on a phone, out of the reach of the workstation protections.
package qrscan

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"  // decoders
	_ "image/jpeg" //
	_ "image/png"  //
	"slices"
	"time"

	"github.com/makiuchi-d/gozxing"
	multiqr "github.com/makiuchi-d/gozxing/multi/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode"
	_ "golang.org/x/image/bmp"  // decoders
	_ "golang.org/x/image/webp" //
)

// Code is a decoded QR code.
type Code struct {
	Text string
	// Source names the image holding it: file name, "page PDF", "image
	// intégrée"...
	Source string
}

// Limits of a scan: the images are third party content.
const (
	// maxPixels bounds the size of a decoded image (a 16 megapixel photo).
	maxPixels = 16 << 20
	// maxImages bounds the images scanned in one file.
	maxImages = 20
	// minSide is the size small images are enlarged to: a QR code stored
	// with one pixel per module is not found otherwise.
	minSide = 400
	// minCode is the smallest QR code (21 modules), maxRatio the most
	// elongated image that can hold one: tracking pixels, lines and
	// banners are skipped.
	minCode  = 21
	maxRatio = 6
	// maxDuration bounds the scan of a mail: a large image takes up to half
	// a second.
	maxDuration = 5 * time.Second
)

// Scanner scans the images of a mail, up to a number of images and a
// duration.
type Scanner struct {
	// Budget is the number of images still allowed.
	Budget int
	// Skipped counts the images not scanned for lack of time or budget.
	Skipped  int
	deadline time.Time
	seen     map[string]bool
}

// NewScanner returns a scanner for one mail.
func NewScanner(budget int) *Scanner {
	return &Scanner{Budget: budget, deadline: time.Now().Add(maxDuration), seen: map[string]bool{}}
}

// allowed reports whether one more image can be scanned, counting it.
func (s *Scanner) allowed() bool {
	if s.Budget <= 0 || time.Now().After(s.deadline) {
		s.Skipped++
		return false
	}
	s.Budget--
	return true
}

// plausible reports whether an image of this size can hold a QR code.
func plausible(width, height int) bool {
	return width >= minCode && height >= minCode && width <= maxRatio*height && height <= maxRatio*width && width*height <= maxPixels
}

// File scans a file according to its content: image, PDF, Office or
// OpenDocument document.
func (s *Scanner) File(name string, data []byte) []Code {
	switch {
	case bytes.HasPrefix(data, []byte("%PDF")):
		return s.pdf(name, data)
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return s.office(name, data)
	}
	return s.Image(name, data)
}

// Image decodes an image and returns its QR codes.
func (s *Scanner) Image(source string, data []byte) []Code {
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || !plausible(config.Width, config.Height) || !s.allowed() {
		return nil
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	return s.decoded(source, img)
}

// decoded returns the QR codes of a decoded image, each text once per
// mail.
func (s *Scanner) decoded(source string, img image.Image) []Code {
	var codes []Code
	for _, text := range scan(img) {
		if !s.seen[text] {
			s.seen[text] = true
			codes = append(codes, Code{Text: text, Source: source})
		}
	}
	return codes
}

// scan looks for QR codes: several in the image first, then one with the
// harder search, on the image and on its negative (light code on a dark
// background).
func scan(img image.Image) []string {
	img = prepare(img)
	hints := map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_TRY_HARDER: true}
	var texts []string
	for _, invert := range []bool{false, true} {
		source := gozxing.NewLuminanceSourceFromImage(img)
		if invert {
			source = source.Invert()
		}
		for _, binarizer := range []func(gozxing.LuminanceSource) gozxing.Binarizer{
			gozxing.NewHybridBinarizer,
			gozxing.NewGlobalHistgramBinarizer,
		} {
			bitmap, err := gozxing.NewBinaryBitmap(binarizer(source))
			if err != nil {
				continue
			}
			if results, err := multiqr.NewQRCodeMultiReader().DecodeMultiple(bitmap, hints); err == nil {
				for _, r := range results {
					if t := r.GetText(); t != "" && !slices.Contains(texts, t) {
						texts = append(texts, t)
					}
				}
			}
			if len(texts) == 0 {
				if r, err := qrcode.NewQRCodeReader().Decode(bitmap, hints); err == nil && r.GetText() != "" {
					texts = append(texts, r.GetText())
				}
			}
			if len(texts) > 0 {
				return texts
			}
		}
	}
	return nil
}

// prepare draws the image on a white background with a margin (the quiet
// zone a cropped code lacks, transparent pixels becoming white), enlarged
// when small.
func prepare(img image.Image) image.Image {
	b := img.Bounds()
	scale := 1
	if side := max(b.Dx(), b.Dy()); side < minSide {
		scale = (minSide + side - 1) / side
	}
	margin := max(b.Dx(), b.Dy()) * scale / 10
	out := image.NewGray(image.Rect(0, 0, b.Dx()*scale+2*margin, b.Dy()*scale+2*margin))
	draw.Draw(out, out.Bounds(), image.White, image.Point{}, draw.Src)
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			c := flatten(img.At(b.Min.X+x, b.Min.Y+y))
			if scale == 1 {
				out.SetGray(margin+x, margin+y, c)
				continue
			}
			for dy := range scale {
				row := out.Pix[(margin+y*scale+dy)*out.Stride+margin+x*scale:]
				for dx := range scale {
					row[dx] = c.Y
				}
			}
		}
	}
	return out
}

// flatten converts a color to gray over a white background.
func flatten(c color.Color) color.Gray {
	r, g, b, a := c.RGBA()
	white := 0xffff - a // premultiplied: add the white showing through
	y := (19595*(r+white) + 38470*(g+white) + 7471*(b+white) + 1<<15) >> 24
	return color.Gray{Y: uint8(min(y, 255))}
}
