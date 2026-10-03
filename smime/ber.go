package smime

import (
	"errors"
	"fmt"
)

// maxDepth bounds the nesting of BER values.
const maxDepth = 64

var errTruncated = errors.New("données BER tronquées")

// berToDER converts a BER encoding (indefinite lengths, constructed
// strings, as produced by streaming S/MIME signers) to DER, which
// encoding/asn1 reads. Definite-length values are copied as they are, so
// that DER input (and the signed attributes) keeps its exact bytes.
func berToDER(ber []byte) ([]byte, error) {
	out, rest, err := convert(ber, 0)
	if err != nil {
		return nil, err
	}
	// Trailing end-of-contents or padding are ignored.
	for _, b := range rest {
		if b != 0 {
			return nil, errors.New("données après la structure BER")
		}
	}
	return out, nil
}

// convert reads one value and returns its DER encoding and the remaining
// input.
func convert(in []byte, depth int) (der, rest []byte, err error) {
	if depth > maxDepth {
		return nil, nil, errors.New("structure BER trop imbriquée")
	}
	tagLen, constructed, tagNumber, class, err := readTag(in)
	if err != nil {
		return nil, nil, err
	}
	tag := in[:tagLen]
	length, lenLen, indefinite, err := readLength(in[tagLen:])
	if err != nil {
		return nil, nil, err
	}
	body := in[tagLen+lenLen:]

	if !indefinite {
		if length > len(body) {
			return nil, nil, errTruncated
		}
		content, after := body[:length], body[length:]
		if !constructed {
			return in[:tagLen+lenLen+length], after, nil
		}
		children, err := convertChildren(content, depth)
		if err != nil {
			return nil, nil, err
		}
		return encode(tag, constructed, tagNumber, class, children), after, nil
	}
	if !constructed {
		return nil, nil, errors.New("longueur indéfinie sur une valeur primitive")
	}
	var children [][]byte
	for {
		if len(body) < 2 {
			return nil, nil, errTruncated
		}
		if body[0] == 0 && body[1] == 0 {
			body = body[2:]
			break
		}
		child, after, err := convert(body, depth+1)
		if err != nil {
			return nil, nil, err
		}
		children = append(children, child)
		body = after
	}
	return encode(tag, constructed, tagNumber, class, children), body, nil
}

func convertChildren(content []byte, depth int) ([][]byte, error) {
	var children [][]byte
	for len(content) > 0 {
		child, after, err := convert(content, depth+1)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		content = after
	}
	return children, nil
}

// encode writes a constructed value. A constructed universal OCTET STRING
// (BER segments) becomes a primitive one, as DER requires.
func encode(tag []byte, constructed bool, tagNumber, class int, children [][]byte) []byte {
	if class == 0 && tagNumber == 4 && constructed {
		var data []byte
		for _, c := range children {
			data = append(data, primitiveContent(c)...)
		}
		return appendTLV([]byte{0x04}, data)
	}
	var content []byte
	for _, c := range children {
		content = append(content, c...)
	}
	return appendTLV(tag, content)
}

// primitiveContent returns the content of a DER value.
func primitiveContent(der []byte) []byte {
	tagLen, _, _, _, err := readTag(der)
	if err != nil {
		return nil
	}
	_, lenLen, _, err := readLength(der[tagLen:])
	if err != nil {
		return nil
	}
	return der[tagLen+lenLen:]
}

func appendTLV(tag, content []byte) []byte {
	out := append([]byte{}, tag...)
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	default:
		var bytes []byte
		for v := n; v > 0; v >>= 8 {
			bytes = append([]byte{byte(v)}, bytes...)
		}
		out = append(out, 0x80|byte(len(bytes)))
		out = append(out, bytes...)
	}
	return append(out, content...)
}

func readTag(in []byte) (n int, constructed bool, number, class int, err error) {
	if len(in) == 0 {
		return 0, false, 0, 0, errTruncated
	}
	b := in[0]
	class, constructed, number = int(b>>6), b&0x20 != 0, int(b&0x1f)
	n = 1
	if number == 0x1f {
		number = 0
		for {
			if n >= len(in) || n > 5 {
				return 0, false, 0, 0, errTruncated
			}
			number = number<<7 | int(in[n]&0x7f)
			n++
			if in[n-1]&0x80 == 0 {
				break
			}
		}
	}
	return n, constructed, number, class, nil
}

func readLength(in []byte) (length, n int, indefinite bool, err error) {
	if len(in) == 0 {
		return 0, 0, false, errTruncated
	}
	b := in[0]
	switch {
	case b < 0x80:
		return int(b), 1, false, nil
	case b == 0x80:
		return 0, 1, true, nil
	}
	count := int(b & 0x7f)
	if count > 4 || len(in) < 1+count {
		return 0, 0, false, fmt.Errorf("longueur BER invalide")
	}
	for _, v := range in[1 : 1+count] {
		length = length<<8 | int(v)
	}
	if length < 0 {
		return 0, 0, false, fmt.Errorf("longueur BER invalide")
	}
	return length, 1 + count, false, nil
}
