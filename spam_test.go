package main

import (
	"strings"
	"testing"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

func reportOf(t *testing.T, reports []spamReport, filter string) spamReport {
	t.Helper()
	for _, r := range reports {
		if r.Filter == filter {
			return r
		}
	}
	t.Fatalf("no %s report in %v", filter, reports)
	return spamReport{}
}

func item(r spamReport, name string) spamItem {
	for _, i := range r.Items {
		if i.Name == name {
			return i
		}
	}
	return spamItem{}
}

func TestSpamReports(t *testing.T) {
	raw := "X-Spam-Status: Yes, score=7.2 required=5.0 tests=BAYES_99=3.5,\r\n\tURIBL_BLACK=1.7,HTML_MESSAGE=0.001,DKIM_VALID=-0.1\r\n\tautolearn=no version=3.4.6\r\n" +
		"X-Spam-Checker-Version: SpamAssassin 3.4.6 on mx.example.net\r\n" +
		"X-Gm-Spam: 0\r\n" +
		"X-Gm-Phishy: 1\r\n" +
		"Received: from mail.sender.example (mail.sender.example [198.51.100.7]) by mx.example.net; Fri, 3 Oct 2025 10:00:00 +0000\r\n" +
		"Received: from localhost (localhost [127.0.0.1]) by mail.sender.example; Fri, 3 Oct 2025 09:59:59 +0000\r\n" +
		"X-Spamd-Result: default: False [-1.00 / 15.00]; R_SPF_ALLOW(-0.20)[+ip4:198.51.100.7]; BAYES_HAM(-3.00)[99%]; SUSPICIOUS_URL(4.50)[]\r\n" +
		"X-Rspamd-Action: no action\r\n" +
		"X-Forefront-Antispam-Report: CIP:198.51.100.7;CTRY:CH;LANG:fr;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:mail.sender.example;PTR:mail.sender.example;CAT:PHSH;SFS:(13230040);DIR:INB;\r\n" +
		"X-Microsoft-Antispam: BCL:0;\r\n" +
		"X-Microsoft-Antispam-Mailbox-Delivery: ucf:0;jmr:0;auth:0;dest:J;OFR:SpamFilterAuthJ;\r\n" +
		"X-Virus-Scanned: amavisd-new\r\n" +
		"From: a@sender.example\r\n\r\nbody\r\n"
	m := mailauth.ParseMessage([]byte(raw))
	hops := mailauth.Hops(m)
	source := mailauth.SourceHop(hops)

	t.Run("receiving server is not Microsoft", func(t *testing.T) {
		reports := spamReports(m, source, map[string]bool{"example.net": true})

		sa := reportOf(t, reports, "SpamAssassin")
		if !sa.Trusted || sa.Verdict != "spam" || sa.Score != "7.2 / 5.0" || len(sa.Rules) != 4 || sa.Rules[0].Name != "BAYES_99" || sa.Rules[3].Score != -0.1 {
			t.Errorf("SpamAssassin = %+v", sa)
		}
		gmail := reportOf(t, reports, "Gmail")
		if !gmail.Trusted || gmail.Level != levelDanger {
			t.Errorf("Gmail = %+v", gmail) // above the source hop
		}
		// Written below the reception: added by the sender.
		rspamd := reportOf(t, reports, "Rspamd")
		if rspamd.Trusted || rspamd.Verdict != "pas de spam" || rspamd.Score != "-1.00 / 15.00" || rspamd.Rules[0].Name != "SUSPICIOUS_URL" {
			t.Errorf("Rspamd = %+v", rspamd)
		}
		ms := reportOf(t, reports, "Microsoft 365 (Exchange Online Protection)")
		if ms.Trusted || ms.Verdict != "phishing" || ms.Level != levelDanger || item(ms, "dest").Level != levelWarning || item(ms, "SCL").Value != "5" || item(ms, "BCL").Value != "0" {
			t.Errorf("Microsoft = %+v", ms)
		}
		other := reportOf(t, reports, "Autres en-têtes de filtrage")
		if len(other.Fields) != 1 || other.Fields[0].Name != "X-Virus-Scanned" {
			t.Errorf("other = %+v", other)
		}

		a := headerAnalysis{Spam: reports}
		if v := a.SpamVerdict(); v.Level != levelDanger || v.Source != "Gmail" {
			t.Errorf("verdict = %+v", v)
		}
	})

	t.Run("received by Microsoft", func(t *testing.T) {
		reports := spamReports(m, source, map[string]bool{"microsoft": true})
		if ms := reportOf(t, reports, "Microsoft 365 (Exchange Online Protection)"); !ms.Trusted {
			t.Errorf("Microsoft report not trusted")
		}
	})

	t.Run("untrusted copy", func(t *testing.T) {
		untrusted := strings.Replace(raw, "X-Forefront-Antispam-Report:", "X-Forefront-Antispam-Report-Untrusted:", 1)
		m := mailauth.ParseMessage([]byte(untrusted))
		reports := spamReports(m, source, map[string]bool{"microsoft": true})
		if ms := reportOf(t, reports, "Microsoft 365 (Exchange Online Protection)"); ms.Trusted {
			t.Errorf("-Untrusted report trusted")
		}
	})

	if a := (headerAnalysis{}); a.SpamVerdict().Result != "aucun" {
		t.Error("no report")
	}
}

func TestIsSpamField(t *testing.T) {
	for name, want := range map[string]bool{
		"X-Forefront-Antispam-Report": true, "X-Spam-Status": true, "X-Rspamd-Queue-Id": true, "X-Pm-Spamscore": true,
		"X-MS-Exchange-Organization-SCL": true, "X-Virus-Scanned": true, "X-Mailer": false, "Subject": false, "X-Received": false, "X-Disclaimer": false,
	} {
		if isSpamField(name) != want {
			t.Errorf("isSpamField(%s) = %v", name, !want)
		}
	}
	if headerCategories[headerCategory("X-Spam-Status")].title != spamCategory || headerCategories[headerCategory("X-Mailer")].title == spamCategory {
		t.Error("antispam category")
	}
}
