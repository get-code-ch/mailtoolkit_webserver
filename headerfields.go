package main

import (
	"html/template"
	"maps"
	"mime"
	"slices"
	"strings"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// templateFuncs are the functions available in the views.
var templateFuncs = template.FuncMap{"resultClass": resultClass, "visibleSpace": visibleSpace, "dkimView": dkimView, "asset": asset, "brands": func() []brand { return brands }}

// dkimView passes a signature and its position to the dkim-signature
// template.
func dkimView(i int, d mailauth.DKIMResult) struct {
	I int
	D mailauth.DKIMResult
} {
	return struct {
		I int
		D mailauth.DKIMResult
	}{i, d}
}

// DKIMFailed reports whether a signature did not verify.
func (a headerAnalysis) DKIMFailed() bool {
	for _, d := range a.DKIM {
		if d.Result != mailauth.ResultPass {
			return true
		}
	}
	return false
}

// headerGroup is a category of header fields shown together.
type headerGroup struct {
	Title  string
	Open   bool
	Fields []fieldView
}

// fieldView is a header field made readable: decoded value, parameters
// split, DKIM signatures covering it.
type fieldView struct {
	Index  int
	Name   string
	Value  string
	Raw    string
	Params []mailauth.Tag
	Signed []signedBy
	// Decoded is set when the value contained RFC 2047 encoded words.
	Decoded bool
}

// signedBy is a DKIM signature covering a field: Sig is its position in
// headerAnalysis.DKIM.
type signedBy struct {
	Sig    int
	Domain string
	Result string
	// Signature is set on the DKIM-Signature field itself.
	Signature bool
}

// headerCategories are the groups, in display order; a field goes to the
// first group whose names or prefixes match it.
var headerCategories = []struct {
	title    string
	open     bool
	names    []string
	prefixes []string
}{
	{"Expéditeur et destinataires", true, []string{"from", "sender", "reply-to", "to", "cc", "bcc", "subject", "date", "message-id",
		"in-reply-to", "references", "return-path", "thread-topic", "thread-index"}, nil},
	{"Authentification", false, []string{"dkim-signature", "authentication-results", "received-spf", "domainkey-signature"},
		[]string{"arc-"}},
	{"Chemin", false, []string{"received", "x-received", "delivered-to", "x-original-to", "envelope-to"}, nil},
	{"Contenu", false, []string{"mime-version"}, []string{"content-"}},
	{"Listes et désabonnement", false, []string{"precedence", "feedback-id"}, []string{"list-"}},
	{spamCategory, false, nil, nil},
	{"Extensions des fournisseurs", false, nil, []string{"x-"}},
	{"Autres", false, nil, []string{""}},
}

// headerGroups sorts the fields of a mail by category, keeping their order
// inside each category. Empty categories are left out.
func headerGroups(m mailauth.Message, dkim []mailauth.DKIMResult) []headerGroup {
	signed := map[int][]signedBy{}
	for i, d := range dkim {
		by := signedBy{Sig: i, Domain: d.Domain, Result: d.Result}
		for _, f := range d.Fields {
			if f.Index >= 0 {
				signed[f.Index] = append(signed[f.Index], by)
			}
		}
		by.Signature = true
		signed[d.SignatureField] = append(signed[d.SignatureField], by)
	}

	groups := make([]headerGroup, len(headerCategories))
	for i, c := range headerCategories {
		groups[i] = headerGroup{Title: c.title, Open: c.open}
	}
	for i, f := range m.Fields {
		value, err := wordDecoder.DecodeHeader(f.Value)
		if err != nil {
			value = f.Value
		}
		view := fieldView{Index: i, Name: f.Name, Value: value, Raw: f.Raw, Decoded: value != f.Value,
			Params: fieldParams(f), Signed: signed[i]}
		groups[headerCategory(f.Name)].Fields = append(groups[headerCategory(f.Name)].Fields, view)
	}
	return slices.DeleteFunc(groups, func(g headerGroup) bool { return len(g.Fields) == 0 })
}

// spamCategory gathers the fields of the antispam filters (isSpamField).
const spamCategory = "Filtrage antispam"

func headerCategory(name string) int {
	name = strings.ToLower(name)
	for i, c := range headerCategories {
		if c.title == spamCategory && isSpamField(name) {
			return i
		}
		if slices.Contains(c.names, name) {
			return i
		}
		for _, prefix := range c.prefixes {
			if strings.HasPrefix(name, prefix) {
				return i
			}
		}
	}
	return len(headerCategories) - 1
}

// fieldParams splits the structured fields worth reading parameter by
// parameter.
func fieldParams(f mailauth.Field) []mailauth.Tag {
	switch name := strings.ToLower(f.Name); name {
	case "dkim-signature", "arc-message-signature", "arc-seal":
		return mailauth.ParseTags(f.Value)
	case "authentication-results", "arc-authentication-results":
		value := f.Value
		var params []mailauth.Tag
		if name == "arc-authentication-results" {
			if instance, rest, ok := strings.Cut(value, ";"); ok && strings.HasPrefix(strings.TrimSpace(instance), "i=") {
				params = append(params, mailauth.Tag{Name: "instance", Value: strings.TrimSpace(instance)})
				value = rest
			}
		}
		results := mailauth.ParseAuthResults(f.Name, value)
		if len(results) > 0 && results[0].Server != "" {
			params = append(params, mailauth.Tag{Name: "serveur", Value: results[0].Server})
		}
		for _, r := range results {
			params = append(params, mailauth.Tag{Name: r.Method, Value: strings.TrimSpace(r.Result + " " + strings.Join(r.Properties, " "))})
		}
		return params
	case "content-type", "content-disposition":
		mediaType, params, err := mime.ParseMediaType(f.Value)
		if err != nil || len(params) == 0 {
			return nil
		}
		tags := []mailauth.Tag{{Name: "type", Value: mediaType}}
		for _, key := range slices.Sorted(maps.Keys(params)) {
			tags = append(tags, mailauth.Tag{Name: key, Value: params[key]})
		}
		return tags
	}
	return nil
}

// visibleSpace shows the characters that matter in a canonicalized field:
// line ends, tabulations and trailing spaces, as marked HTML.
func visibleSpace(s string) template.HTML {
	mark := func(text string) string { return `<span class="ws">` + text + `</span>` }
	var b strings.Builder
	lines := strings.Split(s, "\r\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " ")
		for j, part := range strings.Split(trimmed, "\t") {
			if j > 0 {
				b.WriteString(mark("TAB"))
			}
			b.WriteString(template.HTMLEscapeString(part))
		}
		if spaces := len(line) - len(trimmed); spaces > 0 {
			b.WriteString(mark(strings.Repeat("·", spaces)))
		}
		if i < len(lines)-1 {
			b.WriteString(mark("CRLF") + "\n")
		}
	}
	return template.HTML(b.String())
}
