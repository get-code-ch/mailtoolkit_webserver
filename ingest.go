package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/smtpd"
)

// modeIngest is the envelope mode of the mails received through /ingest.
const modeIngest = "ingest"

// ingest receives a raw mail from Cloudflare Email Routing (an Email Worker,
// see cloudflare/email-worker.js) or any relay that cannot reach the SMTP
// ports. The relay authenticates with "Authorization: Bearer <token>" and
// gives the envelope in X-Envelope-From and X-Envelope-To.
//
// 404 tells the relay to reject the mail (unknown or expired address); the
// other errors are temporary.
func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	if s.ingestToken == "" {
		http.NotFound(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.ingestToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	recipient := strings.ToLower(strings.Trim(strings.TrimSpace(r.Header.Get("X-Envelope-To")), "<>"))
	if !s.store.ValidRecipient(recipient) {
		http.Error(w, "unknown recipient", http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxUploadSize))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	case err != nil:
		http.Error(w, "incomplete message", http.StatusBadRequest)
		return
	case len(data) == 0:
		http.Error(w, "empty message", http.StatusBadRequest)
		return
	}

	env := smtpd.Envelope{
		ID:         smtpd.NewID(),
		Mode:       modeIngest,
		RemoteAddr: s.clientIP(r),
		MailFrom:   strings.Trim(strings.TrimSpace(r.Header.Get("X-Envelope-From")), "<>"),
		Recipients: []string{recipient},
		TLS:        r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		Received:   time.Now().UTC(),
	}
	received := fmt.Sprintf("Received: from email-relay ([%s])\r\n\tby %s with HTTPS id %s\r\n\tfor <%s>;\r\n\t%s\r\n",
		env.RemoteAddr, s.hostname, env.ID, recipient, env.Received.Format(time.RFC1123Z))
	if err := s.store.Deliver(env, append([]byte(received), data...)); err != nil {
		serverError(w, "ingest delivery", err)
		return
	}
	log.Printf("ingest: %s accepted from %s mail_from=<%s> rcpt=%s size=%d", env.ID, env.RemoteAddr, env.MailFrom, recipient, len(data))
	w.WriteHeader(http.StatusNoContent)
}

// cloudflareRanges are the addresses of the Cloudflare proxies
// (https://www.cloudflare.com/ips/).
var cloudflareRanges = mustPrefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(values))
	for i, v := range values {
		prefixes[i] = netip.MustParsePrefix(v)
	}
	return prefixes
}

func isCloudflare(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range cloudflareRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP returns the address of the visitor. Behind Cloudflare, the
// connection comes from a Cloudflare proxy and the visitor is given in
// CF-Connecting-IP; the header is only trusted from a Cloudflare address,
// anyone else could forge it.
func (s *server) clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !s.behindCloudflare {
		return ip
	}
	if addr, err := netip.ParseAddr(ip); err == nil && isCloudflare(addr) {
		if visitor, err := netip.ParseAddr(r.Header.Get("CF-Connecting-IP")); err == nil {
			return visitor.String()
		}
	}
	return ip
}
