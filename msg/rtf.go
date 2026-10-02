package msg

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxRTFSize bounds a decompressed RTF body.
const maxRTFSize = 32 << 20

// The dictionary of compressed RTF starts with this text ([MS-OXRTFCP]
// §2.1.2.1).
const rtfPrebuffer = "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"

const (
	compressedLZFu   = 0x75465A4C // "LZFu"
	uncompressedMELA = 0x414C454D // "MELA"
)

// crcTable is the CRC-32 of [MS-OXRTFCP] §3.1.3.2: the usual polynomial,
// without the initial and final inversions.
var crcTable = crc32.MakeTable(crc32.IEEE)

func rtfCRC(data []byte) uint32 {
	var crc uint32
	for _, b := range data {
		crc = crcTable[byte(crc)^b] ^ (crc >> 8)
	}
	return crc
}

// DecompressRTF decompresses a PR_RTF_COMPRESSED property.
func DecompressRTF(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("msg: compressed RTF too short")
	}
	le := binary.LittleEndian
	compSize := int(le.Uint32(data))
	rawSize := int(le.Uint32(data[4:]))
	compType := le.Uint32(data[8:])
	crc := le.Uint32(data[12:])
	end := min(compSize+4, len(data))
	if end < 16 || rawSize > maxRTFSize {
		return nil, errors.New("msg: invalid compressed RTF header")
	}
	input := data[16:end]

	switch compType {
	case uncompressedMELA:
		return input[:min(rawSize, len(input))], nil
	case compressedLZFu:
	default:
		return nil, errors.New("msg: unknown RTF compression")
	}
	if rtfCRC(input) != crc {
		return nil, errors.New("msg: compressed RTF checksum mismatch")
	}

	var dictionary [4096]byte
	copy(dictionary[:], rtfPrebuffer)
	write := len(rtfPrebuffer)
	out := make([]byte, 0, rawSize)
	for pos := 0; pos < len(input); {
		control := input[pos]
		pos++
		for bit := 0; bit < 8 && pos < len(input); bit++ {
			if control&(1<<bit) == 0 {
				dictionary[write] = input[pos]
				out = append(out, input[pos])
				write = (write + 1) % len(dictionary)
				pos++
				continue
			}
			if pos+1 >= len(input) {
				return out, nil
			}
			reference := int(input[pos])<<8 | int(input[pos+1])
			pos += 2
			offset, length := reference>>4, reference&0xF+2
			if offset == write {
				return out, nil // end marker
			}
			for i := 0; i < length; i++ {
				b := dictionary[(offset+i)%len(dictionary)]
				dictionary[write] = b
				write = (write + 1) % len(dictionary)
				out = append(out, b)
			}
			if len(out) > maxRTFSize {
				return nil, errors.New("msg: decompressed RTF too large")
			}
		}
	}
	return out, nil
}

// Destinations whose content is not text.
var skippedDestinations = map[string]bool{
	"fonttbl": true, "colortbl": true, "stylesheet": true, "info": true, "pict": true, "object": true,
	"listtable": true, "listoverridetable": true, "rsidtbl": true, "generator": true, "xmlnstbl": true,
	"themedata": true, "colorschememapping": true, "latentstyles": true, "datastore": true, "header": true,
	"footer": true, "filetbl": true, "revtbl": true,
}

var symbols = map[string]string{
	"par": "\r\n", "line": "\r\n", "tab": "\t", "lquote": "‘", "rquote": "’", "ldblquote": "“",
	"rdblquote": "”", "bullet": "•", "endash": "–", "emdash": "—", "enspace": " ", "emspace": " ",
}

type rtfState struct {
	skip    bool // ignored destination
	htmlrtf bool // RTF only content, not part of the HTML
	inTag   bool // \*\htmltag destination: original HTML markup
	uc      int  // characters to skip after \uN
}

// HTMLFromRTF extracts the HTML encapsulated in an RTF body
// ([MS-OXRTFEX]). ok is false when the RTF does not encapsulate HTML.
func HTMLFromRTF(rtf []byte) (html string, ok bool) {
	if !strings.Contains(string(rtf[:min(len(rtf), 1024)]), "\\fromhtml1") {
		return "", false
	}
	var out strings.Builder
	var pending []byte // \'hh bytes, decoded together (multi-byte codepages)
	codepage := 1252
	flush := func() {
		if len(pending) > 0 {
			out.WriteString(decodeCodepage(pending, codepage))
			pending = pending[:0]
		}
	}

	state := rtfState{uc: 1}
	var stack []rtfState
	toSkip := 0
	emit := func(s string) {
		if state.skip || (state.htmlrtf && !state.inTag) {
			return
		}
		flush()
		out.WriteString(s)
	}

	for i := 0; i < len(rtf); i++ {
		c := rtf[i]
		switch c {
		case '{':
			stack = append(stack, state)
			toSkip = 0
		case '}':
			if len(stack) > 0 {
				state, stack = stack[len(stack)-1], stack[:len(stack)-1]
			}
			toSkip = 0
		case '\r', '\n':
			// Line breaks of the RTF source are not content.
		case '\\':
			if i+1 >= len(rtf) {
				break
			}
			next := rtf[i+1]
			switch {
			case next == '\'':
				if i+3 < len(rtf) {
					if b, err := strconv.ParseUint(string(rtf[i+2:i+4]), 16, 8); err == nil {
						if toSkip > 0 {
							toSkip--
						} else if !state.skip && (!state.htmlrtf || state.inTag) {
							pending = append(pending, byte(b))
						}
					}
				}
				i += 3
			case next == '{' || next == '}' || next == '\\':
				emit(string(next))
				i++
			case next == '~':
				emit(" ")
				i++
			case next == '\r' || next == '\n':
				emit("\r\n")
				i++
			case next == '*':
				// \*\destination: ignored unless known (htmltag).
				i++
				word, _, _, length := controlWord(rtf[i+1:])
				if strings.HasPrefix(word, "htmltag") {
					state.inTag = true
					state.htmlrtf = false
				} else if word != "" {
					state.skip = true
				}
				i += length
			case isLetter(next):
				word, param, hasParam, length := controlWord(rtf[i:])
				i += length - 1
				switch {
				case skippedDestinations[word]:
					state.skip = true
				case strings.HasPrefix(word, "htmltag"):
					state.inTag = true
				case word == "htmlrtf":
					state.htmlrtf = !hasParam || param != 0
				case word == "ansicpg":
					codepage = param
				case word == "uc":
					state.uc = param
				case word == "u":
					if param < 0 {
						param += 65536
					}
					emit(string(rune(param)))
					toSkip = state.uc
				default:
					if s, ok := symbols[word]; ok {
						emit(s)
					}
				}
			default:
				i++ // other control symbols (\-, \_, \|...)
			}
		default:
			if toSkip > 0 {
				toSkip--
				continue
			}
			if !state.skip && (!state.htmlrtf || state.inTag) {
				flush()
				out.WriteByte(c)
			}
		}
	}
	flush()
	result := out.String()
	if !utf8.ValidString(result) {
		result = strings.ToValidUTF8(result, "�")
	}
	return result, true
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// controlWord parses "\word-123 " at the start of s and returns its total
// length, delimiting space included.
func controlWord(s []byte) (word string, param int, hasParam bool, length int) {
	if len(s) < 2 || s[0] != '\\' || !isLetter(s[1]) {
		return "", 0, false, 0
	}
	i := 1
	for i < len(s) && isLetter(s[i]) {
		i++
	}
	word = string(s[1:i])
	start := i
	if i < len(s) && s[i] == '-' {
		i++
	}
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i > start && !(i == start+1 && s[start] == '-') {
		param, _ = strconv.Atoi(string(s[start:i]))
		hasParam = true
	} else {
		i = start
	}
	if i < len(s) && s[i] == ' ' {
		i++
	}
	return word, param, hasParam, i
}
