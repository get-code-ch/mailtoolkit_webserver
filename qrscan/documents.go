package qrscan

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// maxStream bounds a decompressed PDF image or an Office media file.
const maxStream = 64 << 20

var (
	pdfImage   = regexp.MustCompile(`/Subtype\s*/Image\b`)
	pdfStream  = regexp.MustCompile(`stream\r?\n`)
	pdfInteger = func(key string) *regexp.Regexp { return regexp.MustCompile(`/` + key + `\s+(\d+)(?:\s+\d+\s+R)?`) }
	pdfWidth   = pdfInteger("Width")
	pdfHeight  = pdfInteger("Height")
	pdfBits    = pdfInteger("BitsPerComponent")
	pdfColors  = regexp.MustCompile(`/ColorSpace\s*/Device(Gray|RGB|CMYK)`)
	pdfFilter  = regexp.MustCompile(`/Filter\s*\[?\s*/(\w+)\s*\]?`)
	pdfDecode  = regexp.MustCompile(`/Decode\s*\[\s*1(?:\.0*)?\s+0(?:\.0*)?\b`)
)

// pdf scans the images of a PDF document: JPEG ones (DCTDecode), and raw
// ones compressed with FlateDecode in gray, RGB or CMYK, one or eight bits
// per component, or stencil masks (the usual form of a generated QR code).
// QR codes drawn as vector graphics are not found.
func (s *Scanner) pdf(name string, data []byte) []Code {
	var codes []Code
	n := 0
	for _, loc := range pdfImage.FindAllIndex(data, -1) {
		start := bytes.LastIndex(data[:loc[0]], []byte("<<"))
		next := pdfStream.FindIndex(data[loc[1]:])
		if start < 0 || next == nil {
			continue
		}
		dict := string(data[start : loc[1]+next[0]])
		body := data[loc[1]+next[1]:]
		end := bytes.Index(body, []byte("endstream"))
		if end < 0 {
			continue
		}
		body = bytes.TrimRight(body[:end], "\r\n")
		n++
		source := fmt.Sprintf("%s (image %d)", name, n)
		filter := ""
		if m := pdfFilter.FindStringSubmatch(dict); m != nil {
			filter = m[1]
		}
		switch filter {
		case "DCTDecode":
			codes = append(codes, s.Image(source, body)...)
		case "FlateDecode", "":
			width, height := pdfNumber(pdfWidth, dict), pdfNumber(pdfHeight, dict)
			if !plausible(width, height) || !s.allowed() {
				continue
			}
			if img := rawImage(dict, body, filter != ""); img != nil {
				codes = append(codes, s.decoded(source, img)...)
			}
		}
	}
	return codes
}

// rawImage builds the image of a PDF image stream, nil when unsupported.
func rawImage(dict string, body []byte, compressed bool) image.Image {
	width, height := pdfNumber(pdfWidth, dict), pdfNumber(pdfHeight, dict)
	if width <= 0 || height <= 0 || width*height > maxPixels {
		return nil
	}
	mask := strings.Contains(dict, "/ImageMask true")
	bits, components := pdfNumber(pdfBits, dict), 1
	switch m := pdfColors.FindStringSubmatch(dict); {
	case mask:
		bits = 1
	case m == nil:
		return nil // indexed, ICC based...
	case m[1] == "RGB":
		components = 3
	case m[1] == "CMYK":
		components = 4
	}
	if bits != 1 && bits != 8 {
		return nil
	}
	if compressed {
		r, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil
		}
		body, err = io.ReadAll(io.LimitReader(r, maxStream))
		if err != nil && len(body) == 0 {
			return nil
		}
	}
	rowBytes := (width*components*bits + 7) / 8
	if strings.Contains(dict, "/Predictor") && len(body) >= (rowBytes+1)*height {
		body = unpredict(body, rowBytes, components*bits/8)
	}
	if len(body) < rowBytes*height {
		return nil
	}
	// Black is 0, for gray samples and for stencil masks (painted where
	// 0), unless /Decode [1 0].
	invert := pdfDecode.MatchString(dict)
	img := image.NewGray(image.Rect(0, 0, width, height))
	for y := range height {
		row := body[y*rowBytes:]
		for x := range width {
			var v byte
			switch {
			case bits == 1:
				if row[x/8]&(0x80>>(x%8)) != 0 {
					v = 255
				}
			case components == 1:
				v = row[x]
			case components == 3:
				p := row[x*3:]
				v = byte((299*int(p[0]) + 587*int(p[1]) + 114*int(p[2])) / 1000)
			default:
				p := row[x*4:]
				v = byte(max(0, 255-int(p[3])-(int(p[0])+int(p[1])+int(p[2]))/3))
			}
			if invert {
				v = 255 - v
			}
			img.Pix[y*img.Stride+x] = v
		}
	}
	return img
}

func pdfNumber(re *regexp.Regexp, dict string) int {
	m := re.FindStringSubmatch(dict)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// unpredict reverses the PNG predictors (each row starts with its filter
// type).
func unpredict(data []byte, rowBytes, bpp int) []byte {
	bpp = max(bpp, 1)
	rows := len(data) / (rowBytes + 1)
	out := make([]byte, rows*rowBytes)
	prev := make([]byte, rowBytes)
	for y := range rows {
		in := data[y*(rowBytes+1):]
		filter, src := in[0], in[1:rowBytes+1]
		row := out[y*rowBytes : (y+1)*rowBytes]
		for i := range rowBytes {
			var left, upLeft byte
			if i >= bpp {
				left, upLeft = row[i-bpp], prev[i-bpp]
			}
			up := prev[i]
			switch filter {
			case 1:
				row[i] = src[i] + left
			case 2:
				row[i] = src[i] + up
			case 3:
				row[i] = src[i] + byte((int(left)+int(up))/2)
			case 4:
				row[i] = src[i] + paeth(left, up, upLeft)
			default:
				row[i] = src[i]
			}
		}
		prev = row
	}
	return out
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	}
	return c
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// office scans the images of an Office (word/media/...) or OpenDocument
// (Pictures/...) document.
func (s *Scanner) office(name string, data []byte) []Code {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var codes []Code
	for _, f := range z.File {
		dir := path.Dir(f.Name)
		if path.Base(dir) != "media" && dir != "Pictures" {
			continue
		}
		switch strings.ToLower(path.Ext(f.Name)) {
		case ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp":
		default:
			continue
		}
		if f.UncompressedSize64 > maxStream {
			continue
		}
		r, err := f.Open()
		if err != nil {
			continue
		}
		img, err := io.ReadAll(io.LimitReader(r, maxStream))
		r.Close()
		if err == nil {
			codes = append(codes, s.Image(name+" ("+path.Base(f.Name)+")", img)...)
		}
	}
	return codes
}
