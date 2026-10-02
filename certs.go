package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// certReloader serves a certificate read from files and reloads it when the
// files change, so a renewed certificate (certbot) is used without restart.
type certReloader struct {
	certFile, keyFile string
	// interval between two checks of the files modification time.
	interval time.Duration

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime [2]time.Time
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, interval: 10 * time.Second}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.GetCertificate}
}

// GetCertificate implements tls.Config.GetCertificate. A certificate that
// fails to load is logged and the previous one is kept.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) >= r.interval {
		r.checked = time.Now()
		if modTime, err := r.modTimes(); err == nil && modTime != r.modTime {
			if err := r.reload(); err != nil {
				log.Printf("reloading certificate: %v", err)
			} else {
				log.Printf("certificate %s reloaded", r.certFile)
			}
		}
	}
	return r.cert, nil
}

func (r *certReloader) reload() error {
	modTime, err := r.modTimes()
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.modTime = &cert, modTime
	return nil
}

func (r *certReloader) modTimes() ([2]time.Time, error) {
	var modTime [2]time.Time
	for i, file := range []string{r.certFile, r.keyFile} {
		info, err := os.Stat(file)
		if err != nil {
			return modTime, err
		}
		modTime[i] = info.ModTime()
	}
	return modTime, nil
}
