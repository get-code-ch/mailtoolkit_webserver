package mailauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// SPF results (RFC 7208 §2.6).
const (
	ResultPass      = "pass"
	ResultFail      = "fail"
	ResultSoftFail  = "softfail"
	ResultNeutral   = "neutral"
	ResultNone      = "none"
	ResultPermError = "permerror"
	ResultTempError = "temperror"
)

const (
	maxDNSLookups  = 10
	maxVoidLookups = 2
	maxMXHosts     = 10
)

// SPFResult is the result of an SPF check.
type SPFResult struct {
	Result string
	// Domain is the checked domain (MAIL FROM domain, or HELO).
	Domain string
	IP     netip.Addr
	// Record is the SPF record of Domain.
	Record string
	// Mechanism is the mechanism that matched, if any.
	Mechanism string
	Reason    string
	Lookups   int
}

type spfError struct {
	result string
	reason string
}

func (e *spfError) Error() string { return e.result + ": " + e.reason }

func permError(format string, args ...any) error {
	return &spfError{ResultPermError, fmt.Sprintf(format, args...)}
}

func tempError(format string, args ...any) error {
	return &spfError{ResultTempError, fmt.Sprintf(format, args...)}
}

type spfChecker struct {
	ctx      context.Context
	resolver Resolver
	ip       netip.Addr
	sender   string
	helo     string
	lookups  int
	voids    int
	// top level result details
	record  string
	matched string
}

// CheckSPF evaluates the SPF policy of the sender domain for ip. When
// sender is empty (bounce), the HELO name is checked (RFC 7208 §2.4).
func CheckSPF(ctx context.Context, resolver Resolver, ip netip.Addr, sender, helo string) SPFResult {
	sender = strings.Trim(strings.TrimSpace(sender), "<>")
	if sender == "" {
		sender = "postmaster@" + helo
	} else if !strings.Contains(sender, "@") {
		sender = "postmaster@" + sender
	}
	c := &spfChecker{ctx: ctx, resolver: resolver, ip: ip.Unmap(), sender: sender, helo: helo}
	domain := domainOf(sender)

	result := SPFResult{Domain: domain, IP: c.ip}
	if !c.ip.IsValid() {
		result.Result, result.Reason = ResultNone, "adresse IP de l'expéditeur inconnue"
		return result
	}
	result.Result, result.Reason = c.checkHost(domain, 0)
	result.Record, result.Mechanism, result.Lookups = c.record, c.matched, c.lookups
	return result
}

// checkHost implements check_host() (RFC 7208 §4).
func (c *spfChecker) checkHost(domain string, depth int) (result, reason string) {
	if !validDomain(domain) {
		return ResultNone, "nom de domaine invalide : " + domain
	}
	record, err := c.lookupRecord(domain)
	if err != nil {
		var e *spfError
		if errors.As(err, &e) {
			return e.result, e.reason
		}
		return ResultTempError, err.Error()
	}
	if record == "" {
		return ResultNone, "aucun enregistrement SPF pour " + domain
	}
	if depth == 0 {
		c.record = record
	}

	result, mechanism, err := c.evaluate(domain, record, depth)
	if err != nil {
		var e *spfError
		if errors.As(err, &e) {
			return e.result, e.reason
		}
		return ResultTempError, err.Error()
	}
	if depth == 0 {
		c.matched = mechanism
	}
	if mechanism == "" {
		return result, "aucun mécanisme ne correspond, résultat par défaut"
	}
	return result, "correspond à « " + mechanism + " »"
}

func (c *spfChecker) lookupRecord(domain string) (string, error) {
	txts, err := c.resolver.LookupTXT(c.ctx, domain)
	if isNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", tempError("requête DNS TXT %s : %v", domain, err)
	}
	var records []string
	for _, txt := range txts {
		lower := strings.ToLower(txt)
		if lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ") {
			records = append(records, txt)
		}
	}
	if len(records) > 1 {
		return "", permError("plusieurs enregistrements SPF pour %s", domain)
	}
	if len(records) == 0 {
		return "", nil
	}
	return records[0], nil
}

// evaluate returns the result of a record and the mechanism that matched
// ("" when the default result applies).
func (c *spfChecker) evaluate(domain, record string, depth int) (string, string, error) {
	var redirect string
	for _, term := range strings.Fields(record)[1:] {
		// Modifiers: name=value
		if eq := strings.IndexByte(term, '='); eq > 0 && !strings.ContainsAny(term[:eq], ":/") {
			switch strings.ToLower(term[:eq]) {
			case "redirect":
				if redirect != "" {
					return "", "", permError("modificateur redirect répété")
				}
				redirect = term[eq+1:]
			}
			continue // exp= and unknown modifiers are ignored
		}

		original := term
		qualifier := ResultPass
		switch term[0] {
		case '+':
			term = term[1:]
		case '-':
			qualifier, term = ResultFail, term[1:]
		case '~':
			qualifier, term = ResultSoftFail, term[1:]
		case '?':
			qualifier, term = ResultNeutral, term[1:]
		}
		match, err := c.mechanism(domain, term, depth)
		if err != nil {
			return "", "", err
		}
		if match {
			return qualifier, original, nil
		}
	}

	if redirect != "" {
		if err := c.countLookup(); err != nil {
			return "", "", err
		}
		target, err := c.expand(redirect, domain)
		if err != nil {
			return "", "", err
		}
		result, reason := c.checkHost(target, depth+1)
		if result == ResultNone {
			return "", "", permError("redirect vers %s sans enregistrement SPF", target)
		}
		if result == ResultPermError || result == ResultTempError {
			return "", "", &spfError{result, reason}
		}
		return result, "redirect=" + target, nil
	}
	return ResultNeutral, "", nil
}

func (c *spfChecker) mechanism(domain, term string, depth int) (bool, error) {
	name, arg := term, ""
	if i := strings.IndexAny(term, ":/"); i >= 0 {
		name, arg = term[:i], term[i:]
	}
	switch strings.ToLower(name) {
	case "all":
		return true, nil

	case "include":
		if err := c.countLookup(); err != nil {
			return false, err
		}
		target, err := c.expand(strings.TrimPrefix(arg, ":"), domain)
		if err != nil {
			return false, err
		}
		result, reason := c.checkHost(target, depth+1)
		switch result {
		case ResultPass:
			return true, nil
		case ResultFail, ResultSoftFail, ResultNeutral:
			return false, nil
		case ResultTempError:
			return false, tempError("include:%s : %s", target, reason)
		default:
			return false, permError("include:%s : %s", target, reason)
		}

	case "a", "mx":
		if err := c.countLookup(); err != nil {
			return false, err
		}
		target, prefix4, prefix6, err := c.domainAndPrefixes(arg, domain)
		if err != nil {
			return false, err
		}
		hosts := []string{target}
		if strings.EqualFold(name, "mx") {
			mxs, err := c.resolver.LookupMX(c.ctx, target)
			if err := c.checkLookup(err, len(mxs), "MX "+target); err != nil {
				return false, err
			}
			if len(mxs) > maxMXHosts {
				return false, permError("plus de %d serveurs MX pour %s", maxMXHosts, target)
			}
			hosts = hosts[:0]
			for _, mx := range mxs {
				hosts = append(hosts, strings.TrimSuffix(mx.Host, "."))
			}
		}
		for _, host := range hosts {
			addrs, err := c.lookupIP(host)
			if err != nil {
				return false, err
			}
			for _, addr := range addrs {
				if c.inPrefix(addr, prefix4, prefix6) {
					return true, nil
				}
			}
		}
		return false, nil

	case "ptr":
		// Deprecated (RFC 7208 §5.5) and slow: counted, never matches.
		return false, c.countLookup()

	case "ip4", "ip6":
		prefix, err := parsePrefix(strings.TrimPrefix(arg, ":"), strings.EqualFold(name, "ip4"))
		if err != nil {
			return false, err
		}
		return prefix.Contains(c.ip), nil

	case "exists":
		if err := c.countLookup(); err != nil {
			return false, err
		}
		target, err := c.expand(strings.TrimPrefix(arg, ":"), domain)
		if err != nil {
			return false, err
		}
		addrs, err := c.resolver.LookupNetIP(c.ctx, "ip4", target)
		if err := c.checkLookup(err, len(addrs), "A "+target); err != nil {
			return false, err
		}
		return len(addrs) > 0, nil
	}
	return false, permError("mécanisme inconnu « %s »", term)
}

func (c *spfChecker) countLookup() error {
	c.lookups++
	if c.lookups > maxDNSLookups {
		return permError("plus de %d requêtes DNS (RFC 7208 §4.6.4)", maxDNSLookups)
	}
	return nil
}

// checkLookup counts the void lookups and turns DNS errors into results.
func (c *spfChecker) checkLookup(err error, answers int, what string) error {
	if err != nil && !isNotFound(err) {
		return tempError("requête DNS %s : %v", what, err)
	}
	if err != nil || answers == 0 {
		c.voids++
		if c.voids > maxVoidLookups {
			return permError("plus de %d requêtes DNS sans réponse (RFC 7208 §4.6.4)", maxVoidLookups)
		}
	}
	return nil
}

func (c *spfChecker) lookupIP(host string) ([]netip.Addr, error) {
	network := "ip4"
	if c.ip.Is6() {
		network = "ip6"
	}
	addrs, err := c.resolver.LookupNetIP(c.ctx, network, host)
	if err := c.checkLookup(err, len(addrs), network+" "+host); err != nil {
		return nil, err
	}
	return addrs, nil
}

func (c *spfChecker) inPrefix(addr netip.Addr, bits4, bits6 int) bool {
	addr = addr.Unmap()
	bits := bits4
	if addr.Is6() {
		bits = bits6
	}
	if addr.Is4() != c.ip.Is4() {
		return false
	}
	prefix, err := addr.Prefix(bits)
	return err == nil && prefix.Contains(c.ip)
}

// domainAndPrefixes parses the argument of a/mx: [:domain][/cidr4][//cidr6].
func (c *spfChecker) domainAndPrefixes(arg, domain string) (string, int, int, error) {
	bits4, bits6 := 32, 128
	target := domain
	spec := arg
	if i := strings.Index(spec, "/"); i >= 0 {
		cidr := spec[i:]
		spec = spec[:i]
		parts := strings.SplitN(strings.TrimPrefix(cidr, "/"), "//", 2)
		if strings.HasPrefix(cidr, "//") {
			parts = []string{"", strings.TrimPrefix(cidr, "//")}
		}
		var err error
		if parts[0] != "" {
			if bits4, err = strconv.Atoi(parts[0]); err != nil || bits4 < 0 || bits4 > 32 {
				return "", 0, 0, permError("préfixe IPv4 invalide « %s »", cidr)
			}
		}
		if len(parts) == 2 {
			if bits6, err = strconv.Atoi(parts[1]); err != nil || bits6 < 0 || bits6 > 128 {
				return "", 0, 0, permError("préfixe IPv6 invalide « %s »", cidr)
			}
		}
	}
	if spec = strings.TrimPrefix(spec, ":"); spec != "" {
		var err error
		if target, err = c.expand(spec, domain); err != nil {
			return "", 0, 0, err
		}
	}
	return target, bits4, bits6, nil
}

func parsePrefix(s string, v4 bool) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Is4() != v4 {
			return netip.Prefix{}, permError("adresse invalide « %s »", s)
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil || prefix.Addr().Is4() != v4 {
		return netip.Prefix{}, permError("réseau invalide « %s »", s)
	}
	return prefix.Masked(), nil
}

// expand expands the macros of a domain-spec (RFC 7208 §7).
func (c *spfChecker) expand(spec, domain string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(spec); i++ {
		if spec[i] != '%' {
			b.WriteByte(spec[i])
			continue
		}
		if i+1 >= len(spec) {
			return "", permError("macro incomplète dans « %s »", spec)
		}
		i++
		switch spec[i] {
		case '%':
			b.WriteByte('%')
		case '_':
			b.WriteByte(' ')
		case '-':
			b.WriteString("%20")
		case '{':
			end := strings.IndexByte(spec[i:], '}')
			if end < 0 {
				return "", permError("macro non fermée dans « %s »", spec)
			}
			value, err := c.macro(spec[i+1:i+end], domain)
			if err != nil {
				return "", err
			}
			b.WriteString(value)
			i += end
		default:
			return "", permError("macro invalide dans « %s »", spec)
		}
	}
	return strings.TrimSuffix(b.String(), "."), nil
}

func (c *spfChecker) macro(m, domain string) (string, error) {
	if m == "" {
		return "", permError("macro vide")
	}
	local, senderDomain, _ := strings.Cut(c.sender, "@")
	var value string
	switch m[0] | 0x20 { // lowercase
	case 's':
		value = c.sender
	case 'l':
		value = local
	case 'o':
		value = senderDomain
	case 'd':
		value = domain
	case 'i':
		value = macroIP(c.ip)
	case 'p':
		value = "unknown"
	case 'v':
		value = "in-addr"
		if c.ip.Is6() {
			value = "ip6"
		}
	case 'h':
		value = c.helo
	default:
		return "", permError("macro inconnue %%{%s}", m)
	}

	rest := m[1:]
	digits := 0
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		digits = digits*10 + int(rest[0]-'0')
		rest = rest[1:]
	}
	reverse := false
	if len(rest) > 0 && (rest[0] == 'r' || rest[0] == 'R') {
		reverse, rest = true, rest[1:]
	}
	delimiters := rest
	if delimiters == "" {
		delimiters = "."
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(delimiters, r) })
	if reverse {
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
	}
	if digits > 0 && digits < len(parts) {
		parts = parts[len(parts)-digits:]
	}
	return strings.Join(parts, "."), nil
}

// macroIP formats an IP for %{i}: dotted IPv4, or dotted nibbles for IPv6.
func macroIP(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String()
	}
	b := ip.As16()
	nibbles := make([]string, 0, 32)
	for _, x := range b {
		nibbles = append(nibbles, strconv.FormatUint(uint64(x>>4), 16), strconv.FormatUint(uint64(x&0xf), 16))
	}
	return strings.Join(nibbles, ".")
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}
