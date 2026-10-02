package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// mapResolver answers TXT and A queries from maps.
type mapResolver struct {
	txt map[string][]string
	ip  map[string][]string
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r mapResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := r.txt[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (r mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, v := range r.ip[host] {
		addrs = append(addrs, netip.MustParseAddr(v))
	}
	if len(addrs) == 0 {
		return nil, notFound(host)
	}
	return addrs, nil
}

func (r mapResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, notFound(name)
}

const phishingHeaders = "Return-Path: <bounce@mailer.example>\r\n" +
	"Received: from mx.recipient.example by mx2.recipient.example with LMTP; Mon, 1 Oct 2018 10:00:02 +0000\r\n" +
	"Received: from evil.example (evil.example [203.0.113.66]) by mx.recipient.example with ESMTP id 1; Mon, 1 Oct 2018 10:00:01 +0000\r\n" +
	"Received: from bank.example (bank.example [198.51.100.1]) by evil.example with ESMTP id 0; Mon, 1 Oct 2018 09:00:00 +0000\r\n" +
	"From: \"service@bank.example\" <alert@evil.example>\r\n" +
	"Reply-To: <collect@other.example>\r\n" +
	"Subject: Votre compte\r\n" +
	"Date: Mon, 1 Oct 2018 10:00:00 +0000\r\n" +
	"\r\n" +
	"body\r\n"

func TestAnalyzeHeaders(t *testing.T) {
	resolver := mapResolver{txt: map[string][]string{
		"mailer.example":      {"v=spf1 ip4:203.0.113.0/24 -all"},
		"_dmarc.evil.example": {"v=DMARC1; p=none"},
	}}
	a := analyzeHeaders(context.Background(), resolver, []byte(phishingHeaders), -1)

	if len(a.Hops) != 3 || a.Source != 1 || a.Selected != 1 {
		t.Fatalf("hops %d, source %d, selected %d", len(a.Hops), a.Source, a.Selected)
	}
	if a.SPF.Result != mailauth.ResultPass || a.SPF.Domain != "mailer.example" || a.SPF.IP.String() != "203.0.113.66" {
		t.Errorf("SPF = %+v", a.SPF)
	}
	if len(a.DKIM) != 0 {
		t.Errorf("DKIM = %+v", a.DKIM)
	}
	// SPF passes for mailer.example, which is not aligned with evil.example.
	if a.DMARC.Result != mailauth.ResultFail || a.DMARC.Domain != "evil.example" {
		t.Errorf("DMARC = %+v", a.DMARC)
	}

	// The forged first hop can be chosen manually.
	manual := analyzeHeaders(context.Background(), resolver, []byte(phishingHeaders), 0)
	if manual.Selected != 0 || manual.SPF.IP.String() != "198.51.100.1" || manual.SPF.Result != mailauth.ResultFail {
		t.Errorf("manual hop: selected %d, SPF %+v", manual.Selected, manual.SPF)
	}
	// An invalid hop falls back on the detected one.
	if got := analyzeHeaders(context.Background(), resolver, []byte(phishingHeaders), 42); got.Selected != 1 {
		t.Errorf("invalid hop selected %d", got.Selected)
	}

	want := []string{
		levelDanger + ": Le nom affiché « service@bank.example » contient l'adresse service@bank.example",
		levelWarning + ": Les réponses partiront vers collect@other.example",
		levelInfo + ": Adresse de retour (Return-Path) sur le domaine mailer.example",
		levelWarning + ": Pas d'identifiant Message-ID",
	}
	var got []string
	for _, c := range a.Checks {
		got = append(got, c.Level+": "+c.Message)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || strings.HasPrefix(g, w)
		}
		if !found {
			t.Errorf("missing check %q in %q", w, got)
		}
	}
}

func TestConsistencyChecksLegitimate(t *testing.T) {
	raw := "Return-Path: <bounce@mail.shop.example>\r\n" +
		"From: Shop.example <news@shop.example>\r\n" +
		"Reply-To: support@shop.example\r\n" +
		"Message-ID: <123@mail.shop.example>\r\n" +
		"Date: Mon, 1 Oct 2018 10:00:00 +0000\r\n\r\nbody\r\n"
	if checks := consistencyChecks(mailauth.ParseMessage([]byte(raw)), nil); len(checks) != 0 {
		t.Errorf("legitimate headers flagged: %+v", checks)
	}
	if checks := consistencyChecks(mailauth.ParseMessage([]byte("Subject: x\r\n\r\n")), nil); len(checks) != 1 || checks[0].Level != levelWarning {
		t.Errorf("missing From: %+v", checks)
	}
}
