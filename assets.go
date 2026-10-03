package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// assetVersion changes with the content of the static files: their URLs
// carry it so that browsers and Cloudflare never keep an old version.
var assetVersion string

// staticVersion hashes the files linked by every page.
func staticVersion(folder string) string {
	h := sha256.New()
	for _, name := range []string{"style.css", "app.js", "favicon.svg"} {
		data, err := os.ReadFile(filepath.Join(folder, name))
		if err == nil {
			h.Write(data)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// asset returns the versioned URL of a static file.
func asset(name string) string {
	if assetVersion == "" {
		return "/static/" + name
	}
	return "/static/" + name + "?v=" + assetVersion
}
