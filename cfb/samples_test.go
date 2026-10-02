package cfb

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSamples compares the reader with olefile, the reference Python
// implementation, on real Office files. It runs only when CFB_SAMPLES names
// a folder holding the files and olefile-reference.txt, written by:
//
//	for f in files: print(f, n); for s in streams: print('   ', repr(s), size, sha256[:12])
func TestSamples(t *testing.T) {
	folder := os.Getenv("CFB_SAMPLES")
	if folder == "" {
		t.Skip("CFB_SAMPLES not set")
	}
	reference, err := os.Open(filepath.Join(folder, "olefile-reference.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer reference.Close()

	want := map[string][]string{}
	var current string
	scanner := bufio.NewScanner(reference)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "    ") {
			current = strings.Fields(line)[0]
			continue
		}
		// '\x05SummaryInformation' 4096 a4952f48c6d3
		fields := strings.Fields(line)
		name, err := strconv.Unquote(`"` + strings.ReplaceAll(strings.Trim(fields[0], "'"), `"`, `\"`) + `"`)
		if err != nil {
			t.Fatalf("reference line %q: %v", line, err)
		}
		want[current] = append(want[current], fmt.Sprintf("%q %s %s", name, fields[1], fields[2]))
	}

	for file, streams := range want {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(folder, file))
			if err != nil {
				t.Fatal(err)
			}
			f, err := Open(data)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, e := range f.Entries() {
				if e.Type != TypeStream {
					continue
				}
				content, err := f.ReadStream(e)
				if err != nil {
					t.Fatalf("%s: %v", e.Path, err)
				}
				sum := sha256.Sum256(content)
				got[fmt.Sprintf("%q %d %s", e.Path, e.Size, hex.EncodeToString(sum[:])[:12])] = true
			}
			for _, s := range streams {
				if !got[s] {
					t.Errorf("stream %s not read identically (got %v)", s, got)
				}
			}
			if len(got) != len(streams) {
				t.Errorf("%d streams, olefile finds %d", len(got), len(streams))
			}
		})
	}
}
