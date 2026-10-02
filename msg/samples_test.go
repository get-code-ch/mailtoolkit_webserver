package msg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/get-code-ch/mailtoolkit"
)

// TestSamples reads real Outlook files. It runs only when MSG_SAMPLES names
// a folder of .msg files (for example the example-msg-files of
// msg-extractor, not shipped here because of their license).
func TestSamples(t *testing.T) {
	folder := os.Getenv("MSG_SAMPLES")
	if folder == "" {
		t.Skip("MSG_SAMPLES not set")
	}
	files, _ := filepath.Glob(filepath.Join(folder, "*.msg"))
	if len(files) == 0 {
		t.Fatal("no .msg file in MSG_SAMPLES")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			m, err := Read(data)
			if err != nil {
				t.Fatal(err)
			}
			if m.Subject == "" || (m.Body == "" && m.HTML == "") {
				t.Errorf("subject %q, body %d bytes, html %d bytes", m.Subject, len(m.Body), len(m.HTML))
			}
			converted, err := mailtoolkit.Parse(m.EML())
			if err != nil || converted.Header.Subject == "" || len(converted.Attachments) != len(m.Attachments) {
				t.Errorf("converted: subject %q, %d attachments (want %d), %v",
					converted.Header.Subject, len(converted.Attachments), len(m.Attachments), err)
			}
		})
	}
}
