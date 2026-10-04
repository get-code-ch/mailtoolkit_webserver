package main

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// The site is written in French. The English version translates the
// rendered page: its text nodes and its titles and labels are looked up in
// a catalog of sentences (catalogEN) and of patterns for the sentences
// holding values (patternsEN). The content of the mails, the code and the
// technical values (<code>, <pre>) are never translated.

const (
	langFR = "fr"
	langEN = "en"
	// langCookie remembers the choice of the visitor.
	langCookie = "lang"
)

// language returns the language of a request: the ?lang= parameter or the
// cookie, else English when the browser prefers another language than
// French.
func language(r *http.Request) string {
	if forcedLanguage != "" {
		return forcedLanguage
	}
	for _, v := range []string{r.URL.Query().Get("lang"), cookieValue(r, langCookie)} {
		if v == langFR || v == langEN {
			return v
		}
	}
	accept := strings.TrimSpace(r.Header.Get("Accept-Language"))
	if accept == "" {
		return langFR
	}
	first, _, _ := strings.Cut(accept, ",")
	first, _, _ = strings.Cut(strings.TrimSpace(first), ";")
	if primary, _, _ := strings.Cut(strings.ToLower(first), "-"); primary == "fr" || primary == "*" {
		return langFR
	}
	return langEN
}

func cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

// languageSwitch handles ?lang=: the choice is stored in a cookie and the
// page reloaded without the parameter.
func languageSwitch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := r.URL.Query().Get("lang")
		if r.Method != http.MethodGet || (lang != langFR && lang != langEN) {
			next.ServeHTTP(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: langCookie, Value: lang, Path: "/", MaxAge: int((365 * 24 * time.Hour).Seconds()),
			SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
		query := r.URL.Query()
		query.Del("lang")
		target := url.URL{Path: r.URL.Path, RawQuery: query.Encode()}
		http.Redirect(w, r, target.String(), http.StatusSeeOther)
	})
}

// httpError answers a plain text error in the language of the request.
func httpError(w http.ResponseWriter, r *http.Request, message string, code int) {
	if language(r) == langEN {
		if en, ok := english.translate(message); ok {
			message = en
		}
	}
	http.Error(w, message, code)
}

// translator translates French sentences.
type translator struct {
	exact    map[string]string
	patterns []compiledPattern
	// fallback are the generic patterns, tried last.
	fallback []compiledPattern
}

type compiledPattern struct {
	re *regexp.Regexp
	en string
}

// pattern is a French sentence holding values (%s: any text, %d: a
// number) and its English translation (%s, or %[n]s to reorder).
type pattern struct{ fr, en string }

func newTranslator(exact map[string]string, patterns, fallback []pattern) *translator {
	t := &translator{exact: map[string]string{}, patterns: compilePatterns(patterns), fallback: compilePatterns(fallback)}
	for fr, en := range exact {
		t.exact[normalizeSpace(fr)] = en
	}
	return t
}

// compilePatterns turns the patterns into regular expressions: %s matches
// any text, %d a number.
func compilePatterns(patterns []pattern) []compiledPattern {
	var compiled []compiledPattern
	for _, p := range patterns {
		var re strings.Builder
		re.WriteString("^")
		rest := normalizeSpace(p.fr)
		for {
			i := strings.IndexByte(rest, '%')
			if i < 0 || i+1 == len(rest) {
				re.WriteString(regexp.QuoteMeta(rest))
				break
			}
			re.WriteString(regexp.QuoteMeta(rest[:i]))
			switch rest[i+1] {
			case 's':
				re.WriteString("(.+?)")
			case 'd':
				re.WriteString(`(-?\d+)`)
			default:
				re.WriteString(regexp.QuoteMeta(rest[i : i+2]))
			}
			rest = rest[i+2:]
		}
		re.WriteString("$")
		compiled = append(compiled, compiledPattern{regexp.MustCompile("(?s)" + re.String()), strings.ReplaceAll(p.en, "%d", "%s")})
	}
	return compiled
}

// normalizeSpace collapses the white space, as the HTML rendering does.
func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// translate returns the translation of a sentence, and whether one was
// found.
func (t *translator) translate(s string) (string, bool) {
	return t.translateDepth(normalizeSpace(s), 0)
}

func (t *translator) translateDepth(s string, depth int) (string, bool) {
	if s == "" {
		return "", false
	}
	if en, ok := t.exact[s]; ok {
		return en, true
	}
	if depth > 3 {
		return "", false
	}
	// Punctuation and symbols put by the templates before a message.
	for _, prefix := range []string{": ", "— ", "· ", ", ", "⚠ ", "✓ ", "→ "} {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			if en, ok := t.translateDepth(rest, depth+1); ok {
				return prefix + en, true
			}
		}
	}
	if en, ok := t.match(t.patterns, s, depth); ok {
		return en, true
	}
	// Messages joined by the risk assessment.
	if parts := strings.Split(s, " · "); len(parts) > 1 {
		changed := false
		for i, p := range parts {
			if en := t.translateValue(p, depth+1); en != p {
				parts[i], changed = en, true
			}
		}
		if changed {
			return strings.Join(parts, " · "), true
		}
	}
	return t.match(t.fallback, s, depth)
}

// match translates a sentence with the first pattern matching it.
func (t *translator) match(patterns []compiledPattern, s string, depth int) (string, bool) {
	for _, p := range patterns {
		m := p.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		args := make([]any, len(m)-1)
		for i, v := range m[1:] {
			args[i] = t.translateValue(v, depth+1)
		}
		return fmt.Sprintf(p.en, args...), true
	}
	return "", false
}

// translateValue translates a value of a pattern when it is a sentence of
// the catalog (a message inserted in another one, its first letter
// lowered), else keeps it.
func (t *translator) translateValue(v string, depth int) string {
	if en, ok := t.translateDepth(v, depth); ok {
		return en
	}
	r, size := utf8.DecodeRuneInString(v)
	if unicode.IsLower(r) {
		if en, ok := t.translateDepth(string(unicode.ToUpper(r))+v[size:], depth); ok {
			return lowerFirst(en)
		}
	}
	// A sentence ending with a period, inserted before one.
	if trimmed, ok := strings.CutSuffix(v, "."); ok {
		if en, ok := t.translateDepth(trimmed, depth); ok {
			return en + "."
		}
	}
	return v
}

// translatedAttributes are the attributes holding text for the reader.
var translatedAttributes = map[string]bool{"title": true, "aria-label": true, "placeholder": true, "alt": true}

// voidElements have no end tag.
var voidElements = map[atom.Atom]bool{atom.Area: true, atom.Base: true, atom.Br: true, atom.Col: true, atom.Embed: true, atom.Hr: true,
	atom.Img: true, atom.Input: true, atom.Link: true, atom.Meta: true, atom.Source: true, atom.Track: true, atom.Wbr: true}

// noTranslate reports an element marked translate="no": data of the mail.
func noTranslate(token nethtml.Token) bool {
	for _, a := range token.Attr {
		if a.Key == "translate" && a.Val == "no" {
			return true
		}
	}
	return false
}

// untranslated elements: raw values and scripts. The <code> elements are
// translated only when they hold a sentence of the catalog (a technical
// detail), their values never match it.
var untranslated = map[atom.Atom]bool{atom.Pre: true, atom.Script: true, atom.Style: true, atom.Textarea: true, atom.Kbd: true}

// translateHTML translates a rendered page.
func (t *translator) translateHTML(page []byte, lang string) []byte {
	z := nethtml.NewTokenizer(bytes.NewReader(page))
	var out bytes.Buffer
	out.Grow(len(page) + len(page)/8)
	skip := 0
	for {
		tt := z.Next()
		switch tt {
		case nethtml.ErrorToken:
			return out.Bytes()
		case nethtml.TextToken:
			raw := z.Raw()
			if skip > 0 {
				out.Write(raw)
				continue
			}
			text := html.UnescapeString(string(raw))
			en, ok := t.translate(text)
			if !ok {
				if onUntranslated != nil {
					onUntranslated(normalizeSpace(text))
				}
				out.Write(raw)
				continue
			}
			// The white space around the text is kept, except the French
			// space before a colon.
			lead := text[:len(text)-len(strings.TrimLeftFunc(text, unicode.IsSpace))]
			trail := text[len(strings.TrimRightFunc(text, unicode.IsSpace)):]
			if strings.HasPrefix(en, ":") && lead == " " {
				lead = ""
			}
			out.WriteString(html.EscapeString(lead + en + trail))
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken, nethtml.EndTagToken:
			raw := bytes.Clone(z.Raw())
			token := z.Token()
			void := tt == nethtml.SelfClosingTagToken || voidElements[token.DataAtom]
			if tt == nethtml.EndTagToken {
				if skip > 0 {
					skip--
				}
				out.Write(raw)
				continue
			}
			// Inside an untranslated element, every element opened is
			// counted, so that the region ends with its own end tag.
			if !void && (skip > 0 || untranslated[token.DataAtom] || noTranslate(token)) {
				skip++
			}
			changed := false
			for i, a := range token.Attr {
				switch {
				case token.DataAtom == atom.Html && a.Key == "lang":
					token.Attr[i].Val, changed = lang, true
				case translatedAttributes[a.Key] && skip == 0:
					if en, ok := t.translate(a.Val); ok {
						token.Attr[i].Val, changed = en, true
					} else if onUntranslated != nil {
						onUntranslated(normalizeSpace(a.Val))
					}
				}
			}
			if changed {
				out.WriteString(token.String())
			} else {
				out.Write(raw)
			}
		default:
			out.Write(z.Raw())
		}
	}
}

// Test hooks: forcedLanguage renders every page in a language,
// onUntranslated receives the texts left in French.
var (
	forcedLanguage string
	onUntranslated func(string)
)

// english is the translator of the English version.
var english = newTranslator(catalogEN, patternsEN, fallbackPatternsEN)
