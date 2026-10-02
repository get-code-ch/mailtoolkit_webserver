// Package cfb reads Microsoft Compound File Binary files ([MS-CFB]), the
// container of Office 97-2003 documents, VBA projects and Outlook .msg
// files. The reader is defensive: files come from untrusted mails, so every
// sector chain and directory link is bounded and checked for cycles.
package cfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Signature starts every compound file.
var Signature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

const (
	headerSize    = 512
	dirEntrySize  = 128
	maxRegSect    = 0xFFFFFFFA
	endOfChain    = 0xFFFFFFFE
	freeSect      = 0xFFFFFFFF
	noStream      = 0xFFFFFFFF
	maxDirEntries = 1 << 16
)

// Entry types.
const (
	TypeStorage = 1
	TypeStream  = 2
	TypeRoot    = 5
)

var errCorrupted = errors.New("cfb: corrupted file")

// Entry is a storage (folder) or a stream (file) of the compound file.
type Entry struct {
	Name string
	// Path is the slash separated path from the root, e.g.
	// "Macros/VBA/dir". Names may contain control characters
	// ("\x05SummaryInformation").
	Path  string
	Type  int
	Size  int64
	start uint32
}

// File is an opened compound file.
type File struct {
	data           []byte
	sectorSize     int
	miniSectorSize int
	miniCutoff     int64
	fat            []uint32
	miniFAT        []uint32
	miniStream     []byte
	entries        []Entry
}

type dirEntry struct {
	name               string
	typ                byte
	left, right, child uint32
	start              uint32
	size               int64
}

// IsCFB reports whether data starts with the compound file signature.
func IsCFB(data []byte) bool {
	return bytes.HasPrefix(data, Signature)
}

// Open parses a compound file held in memory.
func Open(data []byte) (*File, error) {
	if len(data) < headerSize || !IsCFB(data) {
		return nil, errors.New("cfb: not a compound file")
	}
	le := binary.LittleEndian
	f := &File{data: data}

	sectorShift := le.Uint16(data[0x1E:])
	miniShift := le.Uint16(data[0x20:])
	if sectorShift != 9 && sectorShift != 12 || miniShift != 6 {
		return nil, fmt.Errorf("cfb: unsupported sector size 2^%d", sectorShift)
	}
	f.sectorSize = 1 << sectorShift
	f.miniSectorSize = 1 << miniShift
	f.miniCutoff = int64(le.Uint32(data[0x38:]))

	numFAT := le.Uint32(data[0x2C:])
	firstDir := le.Uint32(data[0x30:])
	firstMiniFAT := le.Uint32(data[0x3C:])
	firstDIFAT := le.Uint32(data[0x44:])
	numDIFAT := le.Uint32(data[0x48:])
	maxSectors := uint32(len(data)/f.sectorSize + 1)
	if numFAT > maxSectors || numDIFAT > maxSectors {
		return nil, errCorrupted
	}

	// FAT sectors are listed by the DIFAT: 109 entries in the header, then
	// a chain of DIFAT sectors.
	var fatSectors []uint32
	for i := 0; i < 109 && uint32(len(fatSectors)) < numFAT; i++ {
		fatSectors = append(fatSectors, le.Uint32(data[0x4C+4*i:]))
	}
	perDIFAT := f.sectorSize/4 - 1
	next := firstDIFAT
	for n := uint32(0); n < numDIFAT && next <= maxRegSect && uint32(len(fatSectors)) < numFAT; n++ {
		sector, err := f.sector(next)
		if err != nil {
			return nil, err
		}
		for i := 0; i < perDIFAT && uint32(len(fatSectors)) < numFAT; i++ {
			fatSectors = append(fatSectors, le.Uint32(sector[4*i:]))
		}
		next = le.Uint32(sector[4*perDIFAT:])
	}
	for _, s := range fatSectors {
		sector, err := f.sector(s)
		if err != nil {
			return nil, err
		}
		for i := 0; i < f.sectorSize; i += 4 {
			f.fat = append(f.fat, le.Uint32(sector[i:]))
		}
	}

	dir, err := f.readChain(firstDir, -1)
	if err != nil {
		return nil, fmt.Errorf("cfb: directory: %w", err)
	}
	entries, err := parseDirectory(dir, f.sectorSize == 512)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 || entries[0].typ != TypeRoot {
		return nil, errors.New("cfb: no root entry")
	}

	if firstMiniFAT <= maxRegSect {
		miniFAT, err := f.readChain(firstMiniFAT, -1)
		if err != nil {
			return nil, fmt.Errorf("cfb: mini FAT: %w", err)
		}
		for i := 0; i+4 <= len(miniFAT); i += 4 {
			f.miniFAT = append(f.miniFAT, le.Uint32(miniFAT[i:]))
		}
	}
	if root := entries[0]; root.start <= maxRegSect && root.size > 0 {
		if f.miniStream, err = f.readChain(root.start, root.size); err != nil {
			return nil, fmt.Errorf("cfb: mini stream: %w", err)
		}
	}

	f.entries, err = walk(entries)
	return f, err
}

func parseDirectory(dir []byte, version3 bool) ([]dirEntry, error) {
	le := binary.LittleEndian
	count := len(dir) / dirEntrySize
	if count > maxDirEntries {
		return nil, errCorrupted
	}
	entries := make([]dirEntry, count)
	for i := range entries {
		raw := dir[i*dirEntrySize : (i+1)*dirEntrySize]
		nameLen := int(le.Uint16(raw[0x40:]))
		if nameLen > 64 || nameLen%2 != 0 {
			nameLen = 0
		}
		units := make([]uint16, 0, nameLen/2)
		for j := 0; j+2 <= nameLen; j += 2 {
			units = append(units, le.Uint16(raw[j:]))
		}
		e := dirEntry{
			name:  strings.TrimRight(string(utf16.Decode(units)), "\x00"),
			typ:   raw[0x42],
			left:  le.Uint32(raw[0x44:]),
			right: le.Uint32(raw[0x48:]),
			child: le.Uint32(raw[0x4C:]),
			start: le.Uint32(raw[0x74:]),
			size:  int64(le.Uint64(raw[0x78:])),
		}
		if version3 {
			// The high 32 bits may contain garbage in version 3 files.
			e.size &= 0xFFFFFFFF
		}
		entries[i] = e
	}
	return entries, nil
}

// walk flattens the red-black trees of the directory into paths.
func walk(entries []dirEntry) ([]Entry, error) {
	var result []Entry
	visited := make([]bool, len(entries))
	var visit func(id uint32, parent string) error
	visit = func(id uint32, parent string) error {
		if id == noStream {
			return nil
		}
		if int(id) >= len(entries) || visited[id] {
			return errCorrupted
		}
		visited[id] = true
		e := entries[id]
		if err := visit(e.left, parent); err != nil {
			return err
		}
		path := e.name
		if parent != "" {
			path = parent + "/" + e.name
		}
		switch e.typ {
		case TypeStream:
			result = append(result, Entry{Name: e.name, Path: path, Type: TypeStream, Size: e.size, start: e.start})
		case TypeStorage:
			result = append(result, Entry{Name: e.name, Path: path, Type: TypeStorage})
			if err := visit(e.child, path); err != nil {
				return err
			}
		}
		return visit(e.right, parent)
	}
	visited[0] = true
	return result, visit(entries[0].child, "")
}

// Entries returns the storages and streams, in directory order.
func (f *File) Entries() []Entry {
	return f.entries
}

// Find returns the entry at path, compared case insensitively as in CFB.
func (f *File) Find(path string) (Entry, bool) {
	for _, e := range f.entries {
		if strings.EqualFold(e.Path, path) {
			return e, true
		}
	}
	return Entry{}, false
}

// ReadStream returns the content of a stream.
func (f *File) ReadStream(e Entry) ([]byte, error) {
	if e.Type != TypeStream {
		return nil, fmt.Errorf("cfb: %s is not a stream", e.Path)
	}
	if e.Size == 0 {
		return []byte{}, nil
	}
	if e.Size < f.miniCutoff {
		return f.readMiniChain(e.start, e.Size)
	}
	return f.readChain(e.start, e.Size)
}

func (f *File) sector(n uint32) ([]byte, error) {
	offset := int64(n+1) * int64(f.sectorSize)
	if n > maxRegSect || offset+int64(f.sectorSize) > int64(len(f.data)) {
		// The last sector may be truncated in some files.
		if n <= maxRegSect && offset < int64(len(f.data)) {
			sector := make([]byte, f.sectorSize)
			copy(sector, f.data[offset:])
			return sector, nil
		}
		return nil, errCorrupted
	}
	return f.data[offset : offset+int64(f.sectorSize)], nil
}

// readChain reads a chain of sectors; size < 0 reads it all.
func (f *File) readChain(start uint32, size int64) ([]byte, error) {
	if size > int64(len(f.data)) {
		return nil, errCorrupted
	}
	var b bytes.Buffer
	for n, s := 0, start; s != endOfChain; n++ {
		if n > len(f.fat) || int(s) >= len(f.fat) {
			return nil, errCorrupted // cycle or link out of the FAT
		}
		sector, err := f.sector(s)
		if err != nil {
			return nil, err
		}
		b.Write(sector)
		if size >= 0 && int64(b.Len()) >= size {
			break
		}
		s = f.fat[s]
	}
	if size >= 0 {
		if int64(b.Len()) < size {
			return nil, errCorrupted
		}
		return b.Bytes()[:size], nil
	}
	return b.Bytes(), nil
}

func (f *File) readMiniChain(start uint32, size int64) ([]byte, error) {
	if size > int64(len(f.miniStream)) {
		return nil, errCorrupted
	}
	var b bytes.Buffer
	for n, s := 0, start; s != endOfChain && int64(b.Len()) < size; n++ {
		if n > len(f.miniFAT) || int(s) >= len(f.miniFAT) {
			return nil, errCorrupted
		}
		offset := int(s) * f.miniSectorSize
		if offset+f.miniSectorSize > len(f.miniStream) {
			return nil, errCorrupted
		}
		b.Write(f.miniStream[offset : offset+f.miniSectorSize])
		s = f.miniFAT[s]
	}
	if int64(b.Len()) < size {
		return nil, errCorrupted
	}
	return b.Bytes()[:size], nil
}
