package cfb

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/get-code-ch/mailtoolkit_webserver/internal/testcfb"
)

// The real files are checked against olefile in samples_test.go; these
// tests use a minimal version 3 file built here, to cover the corrupted
// cases.

type testEntry struct {
	name               string
	typ                byte
	left, right, child uint32
	start              uint32
	size               uint64
}

var (
	small = bytes.Repeat([]byte("s"), 100)
	big   = bytes.Repeat([]byte("0123456789"), 500)
)

// buildFile lays out: sector 0 FAT, 1 directory, 2 mini FAT, 3 mini stream,
// 4-13 the big stream.
func buildFile(modify func(fat []uint32, dir []testEntry)) []byte {
	le := binary.LittleEndian
	fat := make([]uint32, 128)
	for i := range fat {
		fat[i] = freeSect
	}
	fat[0] = 0xFFFFFFFD // FAT sector
	fat[1], fat[2], fat[3] = endOfChain, endOfChain, endOfChain
	for s := 4; s < 13; s++ {
		fat[s] = uint32(s + 1)
	}
	fat[13] = endOfChain
	dir := []testEntry{
		{"Root Entry", TypeRoot, noStream, noStream, 1, 3, 128},
		{"Small", TypeStream, noStream, 2, noStream, 0, uint64(len(small))},
		{"Dir", TypeStorage, noStream, noStream, 3, 0, 0},
		{"Big", TypeStream, noStream, noStream, noStream, 4, uint64(len(big))},
	}
	if modify != nil {
		modify(fat, dir)
	}

	header := make([]byte, headerSize)
	copy(header, Signature)
	le.PutUint16(header[0x18:], 0x3E)
	le.PutUint16(header[0x1A:], 3)
	le.PutUint16(header[0x1C:], 0xFFFE)
	le.PutUint16(header[0x1E:], 9)
	le.PutUint16(header[0x20:], 6)
	le.PutUint32(header[0x2C:], 1) // FAT sectors
	le.PutUint32(header[0x30:], 1) // first directory sector
	le.PutUint32(header[0x38:], 4096)
	le.PutUint32(header[0x3C:], 2) // first mini FAT sector
	le.PutUint32(header[0x40:], 1)
	le.PutUint32(header[0x44:], endOfChain)
	for i := 0; i < 109; i++ {
		le.PutUint32(header[0x4C+4*i:], freeSect)
	}
	le.PutUint32(header[0x4C:], 0)

	sectors := make([][]byte, 14)
	for i := range sectors {
		sectors[i] = make([]byte, 512)
	}
	for i, v := range fat {
		le.PutUint32(sectors[0][4*i:], v)
	}
	for i, e := range dir {
		raw := sectors[1][i*dirEntrySize:]
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
		le.PutUint64(raw[0x78:], e.size)
	}
	miniFAT := []uint32{1, endOfChain}
	for i := range 128 {
		v := uint32(freeSect)
		if i < len(miniFAT) {
			v = miniFAT[i]
		}
		le.PutUint32(sectors[2][4*i:], v)
	}
	copy(sectors[3], small)
	for i := range 10 {
		copy(sectors[4+i], big[i*512:min((i+1)*512, len(big))])
	}
	return append(header, bytes.Join(sectors, nil)...)
}

func TestOpen(t *testing.T) {
	f, err := Open(buildFile(nil))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range f.Entries() {
		paths = append(paths, e.Path)
	}
	if got := len(paths); got != 3 || paths[0] != "Small" || paths[1] != "Dir" || paths[2] != "Dir/Big" {
		t.Fatalf("entries = %q", paths)
	}
	for path, want := range map[string][]byte{"small": small, "DIR/big": big} {
		e, ok := f.Find(path)
		if !ok {
			t.Fatalf("%s not found", path)
		}
		data, err := f.ReadStream(e)
		if err != nil || !bytes.Equal(data, want) {
			t.Errorf("%s: %d bytes, %v", path, len(data), err)
		}
	}
	if dir, _ := f.Find("Dir"); dir.Type != TypeStorage {
		t.Error("Dir is not a storage")
	}
	if _, err := f.ReadStream(Entry{Path: "Dir", Type: TypeStorage}); err == nil {
		t.Error("reading a storage succeeded")
	}
}

func TestOpenCorrupted(t *testing.T) {
	tests := map[string][]byte{
		"not a compound file": []byte("PK\x03\x04 a zip file, long enough to hold a header ..."),
		"truncated":           buildFile(nil)[:600],
		"directory FAT cycle": buildFile(func(fat []uint32, _ []testEntry) { fat[1] = 1 }),
		"directory cycle":     buildFile(func(_ []uint32, dir []testEntry) { dir[3].right = 2 }),
		"child out of range":  buildFile(func(_ []uint32, dir []testEntry) { dir[2].child = 99 }),
		"sector out of file":  buildFile(func(fat []uint32, _ []testEntry) { fat[1] = 5000 }),
	}
	for name, data := range tests {
		if _, err := Open(data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	// A stream whose chain is too short fails when read.
	f, err := Open(buildFile(func(fat []uint32, _ []testEntry) { fat[6] = endOfChain }))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.Find("Dir/Big")
	if _, err := f.ReadStream(e); err == nil {
		t.Error("short chain read without error")
	}
}

// testcfb, used by the other packages, writes files this reader opens.
func TestOpenBuilt(t *testing.T) {
	large := bytes.Repeat([]byte("abcdefgh"), 1000)
	data := testcfb.Build(
		testcfb.Stream("WordDocument", large),
		testcfb.Storage("Macros",
			testcfb.Storage("VBA", testcfb.Stream("dir", []byte("vba")), testcfb.Stream("ThisDocument", nil)),
			testcfb.Stream("PROJECT", []byte("ID=x")),
		),
		testcfb.Stream("\x05SummaryInformation", []byte{1, 2, 3}),
	)
	f, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range f.Entries() {
		paths = append(paths, e.Path)
	}
	want := "WordDocument,Macros,Macros/VBA,Macros/VBA/dir,Macros/VBA/ThisDocument,Macros/PROJECT,\x05SummaryInformation"
	if got := strings.Join(paths, ","); got != want {
		t.Fatalf("entries = %q", got)
	}
	e, _ := f.Find("worddocument")
	if content, err := f.ReadStream(e); err != nil || !bytes.Equal(content, large) {
		t.Errorf("large stream: %d bytes, %v", len(content), err)
	}
	e, _ = f.Find("Macros/VBA/ThisDocument")
	if content, err := f.ReadStream(e); err != nil || len(content) != 0 {
		t.Errorf("empty stream: %q, %v", content, err)
	}
}
