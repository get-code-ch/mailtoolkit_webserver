package mailauth

import (
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Hop is a parsed Received header: a server that relayed the mail.
type Hop struct {
	Raw string
	// From is the name the sending server gave (HELO), FromHost its
	// reverse DNS name as noted by the receiving server.
	From     string
	FromHost string
	IP       netip.Addr
	By       string
	With     string
	ID       string
	For      string
	Date     time.Time
	// Delay since the previous hop, 0 when unknown.
	Delay time.Duration
}

var (
	bracketIP  = regexp.MustCompile(`\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]`)
	bareIPv4   = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	bareIPv6   = regexp.MustCompile(`\(([0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7})\)`)
	comment    = regexp.MustCompile(`\([^()]*\)`)
	parenHost  = regexp.MustCompile(`\(\s*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\.?\s*[\[(]`)
	clauseWord = regexp.MustCompile(`(?i)^(from|by|via|with|id|for)$`)
)

// ParseReceived parses the value of a Received header (RFC 5321 §4.4). It is
// lenient: every server writes them a bit differently.
func ParseReceived(value string) Hop {
	hop := Hop{Raw: value}
	clauses := value
	if i := strings.LastIndexByte(value, ';'); i >= 0 {
		clauses = value[:i]
		if date, err := mail.ParseDate(strings.TrimSpace(value[i+1:])); err == nil {
			hop.Date = date
		}
	}

	// Split the clauses on their keywords, outside of comments.
	parts := map[string]string{}
	current := ""
	depth := 0
	var word, text strings.Builder
	flush := func() {
		w := word.String()
		word.Reset()
		if depth == 0 && clauseWord.MatchString(w) {
			if current != "" {
				parts[current] += text.String()
			}
			current = strings.ToLower(w)
			text.Reset()
			return
		}
		text.WriteString(w)
	}
	for _, r := range clauses {
		switch {
		case r == '(':
			flush()
			depth++
			text.WriteRune(r)
		case r == ')':
			flush()
			if depth > 0 {
				depth--
			}
			text.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			flush()
			text.WriteRune(' ')
		default:
			word.WriteRune(r)
		}
	}
	flush()
	if current != "" {
		parts[current] += text.String()
	}

	from := parts["from"]
	hop.From = firstWord(from)
	if m := parenHost.FindStringSubmatch(from); m != nil {
		hop.FromHost = strings.ToLower(m[1])
	}
	// The address seen by the receiving server is in the comment; the one
	// before it is what the client claimed in HELO.
	for _, comment := range comment.FindAllString(from, -1) {
		if hop.IP = findIP(comment); hop.IP.IsValid() {
			break
		}
	}
	if !hop.IP.IsValid() {
		hop.IP = findIP(from)
	}
	if !hop.IP.IsValid() {
		// "from [192.0.2.1]" or "from 2001:db8::1"
		hop.IP, _ = netip.ParseAddr(strings.Trim(hop.From, "[]"))
	}
	hop.IP = hop.IP.Unmap()
	hop.By = firstWord(parts["by"])
	hop.With = firstWord(parts["with"])
	hop.ID = firstWord(parts["id"])
	hop.For = strings.Trim(firstWord(parts["for"]), "<>")
	return hop
}

func findIP(s string) netip.Addr {
	for _, re := range []*regexp.Regexp{bracketIP, bareIPv4, bareIPv6} {
		if m := re.FindStringSubmatch(s); m != nil {
			if ip, err := netip.ParseAddr(m[1]); err == nil {
				return ip
			}
		}
	}
	return netip.Addr{}
}

func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 || strings.HasPrefix(fields[0], "(") {
		return ""
	}
	return strings.TrimSuffix(fields[0], ";")
}

// Hops parses the Received headers of a message, oldest first, with the
// delay between consecutive hops.
func Hops(m Message) []Hop {
	values := m.Values("Received")
	hops := make([]Hop, 0, len(values))
	for i := len(values) - 1; i >= 0; i-- {
		hop := ParseReceived(values[i])
		if n := len(hops); n > 0 && !hop.Date.IsZero() && !hops[n-1].Date.IsZero() {
			hop.Delay = hop.Date.Sub(hops[n-1].Date)
		}
		hops = append(hops, hop)
	}
	return hops
}

// SourceHop guesses which hop (index in the oldest first list) received the
// mail from the sender's server: going back from the last hop, the first one
// whose sending server is public and outside of the recipient's provider.
// It returns -1 when no hop has a public IP.
func SourceHop(hops []Hop) int {
	if len(hops) == 0 {
		return -1
	}
	provider := OrgDomain(hops[len(hops)-1].By)
	fallback := -1
	for i := len(hops) - 1; i >= 0; i-- {
		hop := hops[i]
		if !isPublic(hop.IP) {
			continue
		}
		fallback = i
		host := hop.FromHost
		if host == "" {
			host = hop.From
		}
		if provider != "" && strings.Contains(provider, ".") && OrgDomain(host) == provider {
			continue
		}
		return i
	}
	return fallback
}

func isPublic(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !ip.IsMulticast() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(ip) // carrier-grade NAT
}
