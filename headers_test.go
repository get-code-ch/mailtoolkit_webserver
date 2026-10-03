package main

import (
	"context"
	"fmt"
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
	if checks := consistencyChecks(mailauth.ParseMessage([]byte(raw)), nil, nil); len(checks) != 0 {
		t.Errorf("legitimate headers flagged: %+v", checks)
	}
	if checks := consistencyChecks(mailauth.ParseMessage([]byte("Subject: x\r\n\r\n")), nil, nil); len(checks) != 1 || checks[0].Level != levelWarning {
		t.Errorf("missing From: %+v", checks)
	}
}

func verdictOf(a headerAnalysis, name string) authVerdict {
	for _, v := range a.Verdicts {
		if v.Name == name {
			return v
		}
	}
	return authVerdict{}
}

func TestVerdicts(t *testing.T) {
	signature := "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=shop.example; s=k3; h=from; bh=AAAA; b=BBBB\r\n"
	tests := []struct {
		name    string
		headers string
		want    map[string]string // verdict: result level
		warning string            // verdict with a warning
		trusted int
	}{
		{
			name: "Proton validated, body rebuilt by the export",
			headers: "Received: from mail82.sea91.rsgsv.net (mail82.sea91.rsgsv.net [148.105.15.82]) by mailin043.protonmail.ch (Postfix) with ESMTPS id 1; Fri, 11 Sep 2026 08:37:56 +0000\r\n" +
				"Authentication-Results: mail.protonmail.ch; dmarc=pass (p=none dis=none) header.from=shop.example\r\n" +
				"Authentication-Results: mail.protonmail.ch; spf=pass smtp.mailfrom=mail82.sea91.rsgsv.net\r\n" +
				"Authentication-Results: mail.protonmail.ch; dkim=pass (2048-bit key) header.d=shop.example\r\n" + signature,
			want:    map[string]string{"SPF": "pass ok", "DKIM": "pass ok", "DMARC": "pass ok"},
			warning: "DKIM",
			trusted: 3,
		},
		{
			name: "Microsoft 365, no authserv-id",
			headers: "Authentication-Results: spf=pass (sender IP is 203.0.113.10) smtp.mailfrom=shop.example; dkim=pass (signature was verified)\r\n" +
				" header.d=shop.example;dmarc=pass action=none header.from=shop.example;compauth=pass reason=100\r\n" +
				"Received: from mail.shop.example (203.0.113.10) by AM6EUR05FT012.mail.protection.outlook.com (10.233.240.1) with Microsoft SMTP Server id 15.20.1; Mon, 1 Oct 2018 10:00:01 +0000\r\n" + signature,
			want:    map[string]string{"SPF": "pass ok", "DKIM": "pass ok", "DMARC": "pass ok"},
			warning: "DKIM",
			trusted: 4,
		},
		{
			name: "results forged by the sender are ignored",
			headers: "Received: from mail.evil.example (mail.evil.example [203.0.113.66]) by mx.google.com with ESMTPS id 1; Mon, 1 Oct 2018 10:00:01 +0000\r\n" +
				"Authentication-Results: mx.evil.example; dkim=pass header.d=bank.example; spf=pass; dmarc=pass\r\n",
			want:    map[string]string{"DKIM": "none info", "DMARC": "none info"},
			trusted: 0,
		},
		{
			name: "receiving provider failure",
			headers: "Received: from mail.evil.example (mail.evil.example [203.0.113.66]) by mx.google.com with ESMTPS id 1; Mon, 1 Oct 2018 10:00:01 +0000\r\n" +
				"Authentication-Results: mx.google.com; dkim=fail header.d=shop.example; dmarc=fail (p=REJECT) header.from=shop.example\r\n" + signature,
			want:    map[string]string{"DKIM": "fail danger", "DMARC": "fail danger"},
			trusted: 2,
		},
		{
			name:    "internal failure without provider result",
			headers: signature,
			want:    map[string]string{"DKIM": "fail warning"},
			warning: "DKIM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.headers + "From: news@shop.example\r\nSubject: x\r\n\r\nbody\r\n"
			a := analyzeHeaders(context.Background(), mapResolver{}, []byte(raw), -1)
			for name, want := range tt.want {
				v := verdictOf(a, name)
				if got := v.Result + " " + v.Level; got != want {
					t.Errorf("%s = %s (%s), want %s", name, got, v.Source, want)
				}
			}
			for _, v := range a.Verdicts {
				if (v.Warning != "") != (v.Name == tt.warning) {
					t.Errorf("%s warning = %q", v.Name, v.Warning)
				}
			}
			trusted := 0
			for _, p := range a.Provider {
				if p.Trusted {
					trusted++
				}
			}
			if trusted != tt.trusted {
				t.Errorf("%d trusted provider results, want %d: %+v", trusted, tt.trusted, a.Provider)
			}
		})
	}
}

func TestHeaderGroups(t *testing.T) {
	raw := "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from:subject:reply-to; bh=YQ==; b=Yg==\r\n" +
		"Received: from a by b; Fri, 11 Jul 2003 21:00:37 -0700\r\n" +
		"Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=fail header.d=example.com\r\n" +
		"From: =?utf-8?q?Caf=C3=A9?= <joe@example.com>\r\n" +
		"Subject: hello\r\n" +
		"X-Mailer: test\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Foo: bar\r\n\r\nbody\r\n"
	m := mailauth.ParseMessage([]byte(raw))
	dkim := []mailauth.DKIMResult{{Result: mailauth.ResultFail, Domain: "example.com", SignatureField: 0,
		Fields: []mailauth.SignedField{{Name: "from", Index: 3}, {Name: "subject", Index: 4}, {Name: "reply-to", Index: -1}}}}
	groups := headerGroups(m, dkim)

	var got []string
	fields := map[string]fieldView{}
	for _, g := range groups {
		var names []string
		for _, f := range g.Fields {
			names = append(names, f.Name)
			fields[f.Name] = f
		}
		got = append(got, g.Title+"="+strings.Join(names, ","))
	}
	want := "Expéditeur et destinataires=From,Subject|Authentification=DKIM-Signature,Authentication-Results|Chemin=Received|" +
		"Contenu=Content-Type|Extensions des fournisseurs=X-Mailer|Autres=Foo"
	if strings.Join(got, "|") != want {
		t.Errorf("groups %s\nwant %s", strings.Join(got, "|"), want)
	}
	if !groups[0].Open || groups[1].Open {
		t.Error("only the sender group should be open")
	}
	if from := fields["From"]; from.Value != "Café <joe@example.com>" || !from.Decoded || len(from.Signed) != 1 || from.Signed[0].Domain != "example.com" {
		t.Errorf("From = %+v", from)
	}
	if sig := fields["DKIM-Signature"]; len(sig.Signed) != 1 || !sig.Signed[0].Signature || len(sig.Params) != 7 || sig.Params[2] != (mailauth.Tag{Name: "d", Value: "example.com"}) {
		t.Errorf("DKIM-Signature = %+v", sig)
	}
	if ar := fields["Authentication-Results"]; fmt.Sprint(ar.Params) != "[{serveur mx.example.net} {spf pass smtp.mailfrom=example.com} {dkim fail header.d=example.com}]" {
		t.Errorf("Authentication-Results params %v", ar.Params)
	}
	if ct := fields["Content-Type"]; fmt.Sprint(ct.Params) != "[{type text/plain} {charset utf-8}]" {
		t.Errorf("Content-Type params %v", ct.Params)
	}
	if len(fields["X-Mailer"].Signed) != 0 {
		t.Error("X-Mailer is not signed")
	}
}

func TestVisibleSpace(t *testing.T) {
	want := `subject:&lt;a<span class="ws">TAB</span>b<span class="ws">··</span><span class="ws">CRLF</span>` + "\n"
	if got := string(visibleSpace("subject:<a\tb  \r\n")); got != want {
		t.Errorf("visibleSpace = %q", got)
	}
}
