package mailauth

import (
	"strings"
	"testing"
	"time"
)

func TestParseReceived(t *testing.T) {
	tests := []struct {
		value                        string
		from, host, ip, by, with, id string
	}{
		{
			"from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])\r\n        by mx.google.com with SMTPS id x1sor123;\r\n        Fri, 31 Aug 2018 10:19:29 -0700 (PDT)",
			"mail-sor-f41.google.com", "mail-sor-f41.google.com", "209.85.220.41", "mx.google.com", "SMTPS", "x1sor123",
		},
		{
			"from mail.sender.example (203.0.113.10) by AM6EUR05FT012.mail.protection.outlook.com (10.233.240.1) with Microsoft SMTP Server id 15.20.1; Mon, 1 Oct 2018 10:00:00 +0000",
			"mail.sender.example", "", "203.0.113.10", "AM6EUR05FT012.mail.protection.outlook.com", "Microsoft", "15.20.1",
		},
		{
			"from [192.168.1.20] (unknown [10.0.0.5]) by mail.sender.example (Postfix) with ESMTPSA id 4A2B3C for <a@b.example>; Fri, 31 Aug 2018 19:18:35 +0200",
			"[192.168.1.20]", "", "10.0.0.5", "mail.sender.example", "ESMTPSA", "4A2B3C",
		},
		{
			"from host.example ([2001:db8::25]) by mx.example.org with esmtp (Exim 4.92) (envelope-from <x@host.example>) id 1abc-0001; Tue, 02 Oct 2018 08:00:00 +0000",
			"host.example", "", "2001:db8::25", "mx.example.org", "esmtp", "1abc-0001",
		},
		{
			"by 2002:a05:6000:1a8a:b0:2f8:: with SMTP id x; Fri, 31 Aug 2018 10:19:30 -0700 (PDT)",
			"", "", "", "2002:a05:6000:1a8a:b0:2f8::", "SMTP", "x",
		},
	}
	for _, tt := range tests {
		hop := ParseReceived(tt.value)
		ip := ""
		if hop.IP.IsValid() {
			ip = hop.IP.String()
		}
		if hop.From != tt.from || hop.FromHost != tt.host || ip != tt.ip || hop.By != tt.by || hop.With != tt.with || hop.ID != tt.id {
			t.Errorf("ParseReceived(%.40q) = from %q host %q ip %q by %q with %q id %q", tt.value, hop.From, hop.FromHost, ip, hop.By, hop.With, hop.ID)
		}
		if hop.Date.IsZero() {
			t.Errorf("date not parsed in %.40q", tt.value)
		}
	}
	if hop := ParseReceived("from a by b for <user@example.com>; garbage"); hop.For != "user@example.com" || !hop.Date.IsZero() {
		t.Errorf("for/date: %+v", hop)
	}
}

func buildMessage(received ...string) Message {
	var b strings.Builder
	for _, r := range received {
		b.WriteString("Received: " + r + "\r\n")
	}
	b.WriteString("From: a@example.com\r\n\r\nbody\r\n")
	return ParseMessage([]byte(b.String()))
}

func TestSourceHop(t *testing.T) {
	gmail := buildMessage(
		"by 2002:a05:6000:1a8a:b0:2f8:: with SMTP id x; Fri, 31 Aug 2018 10:19:31 -0700",
		"from mail.sender.example (mail.sender.example. [203.0.113.10]) by mx.google.com with ESMTPS id y; Fri, 31 Aug 2018 10:19:30 -0700",
		"from [192.168.1.20] (unknown [10.0.0.5]) by mail.sender.example (Postfix) with ESMTPSA id z; Fri, 31 Aug 2018 19:19:20 +0200",
	)
	hops := Hops(gmail)
	if len(hops) != 3 || hops[0].By != "mail.sender.example" {
		t.Fatalf("hops not oldest first: %+v", hops)
	}
	if hops[1].Delay != 10*time.Second || hops[2].Delay != time.Second {
		t.Errorf("delays = %v, %v", hops[1].Delay, hops[2].Delay)
	}
	if got := SourceHop(hops); got != 1 {
		t.Errorf("gmail source hop = %d, want 1", got)
	}

	outlook := buildMessage(
		"from AM6PR05MB1234.eurprd05.prod.outlook.com (2603:10a6:20b::1) by DB9PR05MB5678.eurprd05.prod.outlook.com with HTTPS; Mon, 1 Oct 2018 10:00:03 +0000",
		"from AM6EUR05FT012.eop-eur05.prod.protection.outlook.com (2603:10a6:208::2) by AM6PR05MB1234.eurprd05.prod.outlook.com (2603:10a6:20b::1) with Microsoft SMTP Server; Mon, 1 Oct 2018 10:00:02 +0000",
		"from mail.sender.example (203.0.113.10) by AM6EUR05FT012.mail.protection.outlook.com (10.233.240.1) with Microsoft SMTP Server id 15.20.1; Mon, 1 Oct 2018 10:00:01 +0000",
		"from laptop (unknown [192.168.0.2]) by mail.sender.example with ESMTPSA; Mon, 1 Oct 2018 10:00:00 +0000",
	)
	hops = Hops(outlook)
	if got := SourceHop(hops); got != 1 || hops[got].IP.String() != "203.0.113.10" {
		t.Errorf("outlook source hop = %d", got)
	}

	if got := SourceHop(Hops(buildMessage("from localhost (localhost [127.0.0.1]) by mx.example.org; Mon, 1 Oct 2018 10:00:00 +0000"))); got != -1 {
		t.Errorf("only private hops: %d, want -1", got)
	}
	if got := SourceHop(nil); got != -1 {
		t.Errorf("no hop: %d", got)
	}
}

func TestProviderResults(t *testing.T) {
	m := ParseMessage([]byte("Authentication-Results: mx.google.com;\r\n" +
		"       dkim=pass header.i=@example.com header.s=s1 header.b=abc;\r\n" +
		"       spf=pass (google.com: domain of x@example.com designates 203.0.113.10 as permitted sender; ok) smtp.mailfrom=x@example.com;\r\n" +
		"       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com\r\n" +
		"ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=fail smtp.mailfrom=y.test\r\n" +
		"Received-SPF: Pass (protection.outlook.com: domain of example.com designates 203.0.113.10) receiver=x; client-ip=203.0.113.10\r\n" +
		"From: a@example.com\r\n\r\n"))
	results := ProviderResults(m)
	want := []string{"mx.google.com dkim=pass", "mx.google.com spf=pass", "mx.google.com dmarc=pass", "mx.microsoft.com spf=fail", " spf=pass"}
	if len(results) != len(want) {
		t.Fatalf("%d results: %+v", len(results), results)
	}
	for i, r := range results {
		if got := r.Server + " " + r.Method + "=" + r.Result; got != want[i] {
			t.Errorf("result %d = %q, want %q", i, got, want[i])
		}
	}
	if strings.Join(results[1].Properties, " ") != "smtp.mailfrom=x@example.com" {
		t.Errorf("spf properties = %q", results[1].Properties)
	}
}

func TestProviderResultsWithoutServer(t *testing.T) {
	m := ParseMessage([]byte("Authentication-Results: spf=pass (sender IP is 203.0.113.10) smtp.mailfrom=shop.example; dkim=pass\r\n" +
		" (signature was verified) header.d=shop.example;dmarc=pass action=none header.from=shop.example\r\n\r\n"))
	results := ProviderResults(m)
	var got []string
	for _, r := range results {
		got = append(got, r.Server+"|"+r.Method+"="+r.Result)
	}
	if strings.Join(got, " ") != "|spf=pass |dkim=pass |dmarc=pass" {
		t.Errorf("results = %q", got)
	}
}
