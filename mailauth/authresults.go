package mailauth

import "strings"

// ProviderResult is an authentication result recorded by a server the mail
// went through (Authentication-Results, ARC-Authentication-Results,
// Received-SPF).
type ProviderResult struct {
	Header string
	// Server is the authserv-id, the server that ran the check.
	Server string
	Method string
	Result string
	// Properties are the details (smtp.mailfrom=..., header.d=...).
	Properties []string
}

// ProviderResults returns the authentication results found in the headers,
// top (most recent) first.
func ProviderResults(m Message) []ProviderResult {
	var results []ProviderResult
	for _, f := range m.Fields {
		switch strings.ToLower(f.Name) {
		case "authentication-results":
			results = append(results, parseAuthResults(f.Name, f.Value)...)
		case "arc-authentication-results":
			// "i=1; server; method=result ..."
			value := f.Value
			if instance, rest, ok := strings.Cut(value, ";"); ok && strings.HasPrefix(strings.TrimSpace(instance), "i=") {
				value = rest
			}
			results = append(results, parseAuthResults(f.Name, value)...)
		case "received-spf":
			result := strings.ToLower(firstWord(f.Value))
			if result != "" {
				results = append(results, ProviderResult{Header: f.Name, Method: "spf", Result: result,
					Properties: strings.Fields(removeComments(f.Value))[1:]})
			}
		}
	}
	return results
}

// parseAuthResults parses an Authentication-Results value (RFC 8601).
func parseAuthResults(header, value string) []ProviderResult {
	parts := strings.Split(removeComments(value), ";")
	server := strings.Fields(parts[0])
	var results []ProviderResult
	for _, part := range parts[1:] {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		method, result, ok := strings.Cut(fields[0], "=")
		if !ok {
			continue // "none" means no result
		}
		r := ProviderResult{Header: header, Method: strings.ToLower(method), Result: strings.ToLower(result), Properties: fields[1:]}
		if len(server) > 0 {
			r.Server = server[0]
		}
		results = append(results, r)
	}
	return results
}

// removeComments removes the (comments) of a structured header value.
func removeComments(s string) string {
	var b strings.Builder
	depth := 0
	quoted := false
	for _, r := range s {
		switch {
		case r == '"' && depth == 0:
			quoted = !quoted
			b.WriteRune(r)
		case r == '(' && !quoted:
			depth++
		case r == ')' && !quoted && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}
