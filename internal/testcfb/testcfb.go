// Package testcfb builds compound files (Office 97-2003, .msg) for tests.
// It writes version 3 files without mini stream: every stream uses regular
// sectors, which the format allows when the mini stream cutoff is 0.
package testcfb

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// Node is a stream, or a storage when Children is not nil.
type Node struct {
	Name     string
	Data     []byte
	Children []Node
}

// Stream and Storage build nodes.
func Stream(name string, data []byte) Node { return Node{Name: name, Data: data} }

func Storage(name string, children ...Node) Node {
	return Node{Name: name, Children: append([]Node{}, children...)}
}

const (
	sectorSize = 512
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
	fatSect    = 0xFFFFFFFD
	noStream   = 0xFFFFFFFF
)

type entry struct {
	name               string
	typ                byte
	left, right, child uint32
	data               []byte
	start              uint32
}

// Build returns a compound file holding nodes at its root.
func Build(nodes ...Node) []byte {
	entries := []entry{{name: "Root Entry", typ: 5, left: noStream, right: noStream, child: noStream}}
	var add func(parent int, children []Node)
	add = func(parent int, children []Node) {
		previous := -1
		for _, n := range children {
			id := len(entries)
			e := entry{name: n.Name, typ: 2, left: noStream, right: noStream, child: noStream, data: n.Data}
			if n.Children != nil {
				e.typ = 1
			}
			entries = append(entries, e)
			// Siblings are chained through their right link: a valid,
			// unbalanced, binary tree.
			if previous < 0 {
				entries[parent].child = uint32(id)
			} else {
				entries[previous].right = uint32(id)
			}
			previous = id
			if n.Children != nil {
				add(id, n.Children)
			}
		}
	}
	add(0, nodes)

	sectorsFor := func(n int) int { return (n + sectorSize - 1) / sectorSize }
	dirSectors := sectorsFor(len(entries) * 128)
	dataSectors := 0
	for _, e := range entries {
		dataSectors += sectorsFor(len(e.data))
	}
	fatSectors := 1
	for fatSectors*sectorSize/4 < fatSectors+dirSectors+dataSectors {
		fatSectors++
	}

	fat := make([]uint32, fatSectors*sectorSize/4)
	for i := range fat {
		fat[i] = freeSect
	}
	next := 0
	chain := func(count int) uint32 {
		if count == 0 {
			return endOfChain
		}
		start := next
		for i := 0; i < count; i++ {
			fat[next] = uint32(next + 1)
			next++
		}
		fat[next-1] = endOfChain
		return uint32(start)
	}
	for i := 0; i < fatSectors; i++ {
		fat[next] = fatSect
		next++
	}
	dirStart := chain(dirSectors)
	for i := range entries {
		entries[i].start = chain(sectorsFor(len(entries[i].data)))
	}

	le := binary.LittleEndian
	var b bytes.Buffer
	header := make([]byte, sectorSize)
	copy(header, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	le.PutUint16(header[0x18:], 0x3E)
	le.PutUint16(header[0x1A:], 3)
	le.PutUint16(header[0x1C:], 0xFFFE)
	le.PutUint16(header[0x1E:], 9)
	le.PutUint16(header[0x20:], 6)
	le.PutUint32(header[0x2C:], uint32(fatSectors))
	le.PutUint32(header[0x30:], dirStart)
	le.PutUint32(header[0x38:], 0) // no mini stream
	le.PutUint32(header[0x3C:], endOfChain)
	le.PutUint32(header[0x44:], endOfChain)
	for i := 0; i < 109; i++ {
		v := uint32(freeSect)
		if i < fatSectors {
			v = uint32(i)
		}
		le.PutUint32(header[0x4C+4*i:], v)
	}
	b.Write(header)

	for _, v := range fat {
		binary.Write(&b, le, v)
	}
	dir := make([]byte, dirSectors*sectorSize)
	for i, e := range entries {
		raw := dir[i*128:]
		name := utf16.Encode([]rune(e.name + "\x00"))
		for j, u := range name {
			le.PutUint16(raw[2*j:], u)
		}
		le.PutUint16(raw[0x40:], uint16(2*len(name)))
		raw[0x42], raw[0x43] = e.typ, 1
		le.PutUint32(raw[0x44:], e.left)
		le.PutUint32(raw[0x48:], e.right)
		le.PutUint32(raw[0x4C:], e.child)
		le.PutUint32(raw[0x74:], e.start)
		le.PutUint64(raw[0x78:], uint64(len(e.data)))
	}
	for i := len(entries); i < dirSectors*4; i++ {
		raw := dir[i*128:]
		le.PutUint32(raw[0x44:], noStream)
		le.PutUint32(raw[0x48:], noStream)
		le.PutUint32(raw[0x4C:], noStream)
	}
	b.Write(dir)
	for _, e := range entries {
		if len(e.data) > 0 {
			padded := make([]byte, sectorsFor(len(e.data))*sectorSize)
			copy(padded, e.data)
			b.Write(padded)
		}
	}
	return b.Bytes()
}
