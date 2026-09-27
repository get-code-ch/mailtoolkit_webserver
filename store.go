package main

import (
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/get-code-ch/mailtoolkit"
)

var errNotFound = errors.New("mail not found")

type cachedMail struct {
	mail    mailtoolkit.Mail
	modTime time.Time
	size    int64
}

// mailStore parses the mails of a folder on demand and caches them until the
// file changes. It is safe for concurrent use.
type mailStore struct {
	root *os.Root
	ext  string

	mu    sync.RWMutex
	mails map[string]cachedMail
}

func newMailStore(folder, ext string) (*mailStore, error) {
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, err
	}
	return &mailStore{root: root, ext: ext, mails: make(map[string]cachedMail)}, nil
}

// accepts reports whether name is a mail file id served by the store. Ids are
// plain file names: sub folders and hidden files are rejected.
func (s *mailStore) accepts(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.ContainsAny(name, `/\`) {
		return false
	}
	return s.ext == ".*" || filepath.Ext(name) == s.ext
}

// ids lists the mail files of the folder, sorted by name, and forgets the
// cached mails whose file was removed.
func (s *mailStore) ids() ([]string, error) {
	dir, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	var ids []string
	present := make(map[string]bool)
	for _, entry := range entries {
		if entry.Type().IsRegular() && s.accepts(entry.Name()) {
			ids = append(ids, entry.Name())
			present[entry.Name()] = true
		}
	}
	sort.Strings(ids)

	s.mu.Lock()
	for id := range s.mails {
		if !present[id] {
			delete(s.mails, id)
		}
	}
	s.mu.Unlock()

	return ids, nil
}

// get returns the parsed mail, reparsing the file when it changed. A mail
// that could only be partially parsed is logged and returned as is.
func (s *mailStore) get(id string) (mailtoolkit.Mail, error) {
	if !s.accepts(id) {
		return mailtoolkit.Mail{}, errNotFound
	}
	info, err := s.root.Stat(id)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return mailtoolkit.Mail{}, errNotFound
	}
	if err != nil {
		return mailtoolkit.Mail{}, err
	}

	s.mu.RLock()
	cached, ok := s.mails[id]
	s.mu.RUnlock()
	if ok && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
		return cached.mail, nil
	}

	file, err := s.root.Open(id)
	if err != nil {
		return mailtoolkit.Mail{}, err
	}
	defer file.Close()
	buffer, err := io.ReadAll(file)
	if err != nil {
		return mailtoolkit.Mail{}, err
	}
	mail, err := mailtoolkit.Parse(buffer)
	if err != nil {
		log.Printf("mail %s: %v", id, err)
	}

	s.mu.Lock()
	s.mails[id] = cachedMail{mail: mail, modTime: info.ModTime(), size: info.Size()}
	s.mu.Unlock()
	return mail, nil
}
