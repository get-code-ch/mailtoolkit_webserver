package mailauth

import (
	"context"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DMARCResult is the DMARC evaluation of the From domain.
type DMARCResult struct {
	Result string // pass, fail, none, temperror, permerror
	// Domain is the From domain, OrgDomain its organizational domain.
	Domain    string
	OrgDomain string
	Record    string
	// Policy is the policy requested for this domain: none, quarantine or
	// reject (sp= when the record comes from the organizational domain).
	Policy string
	Pct    int
	// SPFAligned and DKIMAligned tell which authentication passed and is
	// aligned with the From domain.
	SPFAligned  bool
	DKIMAligned bool
	// DKIMDomain is the domain of the aligned DKIM signature.
	DKIMDomain string
	Reason     string
}

// OrgDomain returns the organizational domain (public suffix + 1 label):
// mail.bank.co.uk -> bank.co.uk.
func OrgDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if org, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return org
	}
	return domain
}

// CheckDMARC evaluates the DMARC policy of fromDomain from the SPF and DKIM
// results.
func CheckDMARC(ctx context.Context, resolver Resolver, fromDomain string, spf SPFResult, dkim []DKIMResult) DMARCResult {
	fromDomain = strings.TrimSuffix(strings.ToLower(fromDomain), ".")
	result := DMARCResult{Domain: fromDomain, OrgDomain: OrgDomain(fromDomain)}
	if fromDomain == "" {
		result.Result, result.Reason = ResultPermError, "domaine de l'expéditeur (From) introuvable"
		return result
	}

	record, tags, err := lookupDMARC(ctx, resolver, fromDomain)
	subdomain := false
	if err == nil && record == "" && result.OrgDomain != fromDomain {
		record, tags, err = lookupDMARC(ctx, resolver, result.OrgDomain)
		subdomain = true
	}
	if err != nil {
		result.Result, result.Reason = ResultTempError, err.Error()
		return result
	}
	if record == "" {
		result.Result, result.Reason = ResultNone, "le domaine ne publie pas de politique DMARC"
		return result
	}
	result.Record = record

	result.Policy = strings.ToLower(tags["p"])
	if subdomain && tags["sp"] != "" {
		result.Policy = strings.ToLower(tags["sp"])
	}
	if result.Policy != "none" && result.Policy != "quarantine" && result.Policy != "reject" {
		result.Policy = "none"
	}
	result.Pct = 100
	if pct, err := strconv.Atoi(tags["pct"]); err == nil && pct >= 0 && pct <= 100 {
		result.Pct = pct
	}
	strictSPF, strictDKIM := strings.EqualFold(tags["aspf"], "s"), strings.EqualFold(tags["adkim"], "s")

	result.SPFAligned = spf.Result == ResultPass && aligned(spf.Domain, fromDomain, strictSPF)
	for _, d := range dkim {
		if d.Result == ResultPass && aligned(d.Domain, fromDomain, strictDKIM) {
			result.DKIMAligned, result.DKIMDomain = true, d.Domain
			break
		}
	}

	if result.SPFAligned || result.DKIMAligned {
		result.Result = ResultPass
		var by []string
		if result.SPFAligned {
			by = append(by, "SPF ("+spf.Domain+")")
		}
		if result.DKIMAligned {
			by = append(by, "DKIM ("+result.DKIMDomain+")")
		}
		result.Reason = "authentifié et aligné par " + strings.Join(by, " et ")
		return result
	}
	result.Result = ResultFail
	result.Reason = "ni SPF ni DKIM ne valident un domaine aligné sur " + fromDomain
	return result
}

func aligned(domain, fromDomain string, strict bool) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if strict {
		return domain == fromDomain
	}
	return domain != "" && OrgDomain(domain) == OrgDomain(fromDomain)
}

// lookupDMARC returns the DMARC record of a domain ("" if none).
func lookupDMARC(ctx context.Context, resolver Resolver, domain string) (string, map[string]string, error) {
	txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain)
	if isNotFound(err) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, tempError("requête DNS _dmarc.%s : %v", domain, err)
	}
	var record string
	var tags map[string]string
	for _, txt := range txts {
		parsed, err := parseTags(txt)
		if err != nil || parsed["v"] != "DMARC1" || !strings.HasPrefix(strings.TrimSpace(txt), "v") {
			continue
		}
		if record != "" {
			return "", nil, nil // several records: no policy (RFC 7489 §6.6.3)
		}
		record, tags = txt, parsed
	}
	return record, tags, nil
}
