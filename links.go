package main

import (
	"bytes"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/get-code-ch/mailtoolkit"
	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/net/idna"
)

// Warning levels, from the most to the least severe.
const (
	levelDanger  = "danger"
	levelWarning = "warning"
	levelInfo    = "info"
)

type LinkWarning struct {
	Level   string
	Message string
}

// Link is a URL found in a mail, with what the reader sees of it.
type Link struct {
	URL string
	// Host is the destination host, in Unicode when it is internationalized.
	Host string
	// Text is the text displayed for the link (anchor text, image alt...).
	Text string
	// Source describes where the URL was found: "lien", "image", "formulaire"...
	Source string
	// Part is the content part the link comes from (text/html, text/plain).
	Part  string
	Count int
	// Target is the final destination when the URL redirects through a
	// parameter (Safe Links, trackers...).
	Target   string
	Warnings []LinkWarning
}

// Level returns the most severe warning level of the link, "" if none.
func (l Link) Level() string {
	level := ""
	for _, w := range l.Warnings {
		switch {
		case w.Level == levelDanger:
			return levelDanger
		case w.Level == levelWarning:
			level = levelWarning
		case level == "":
			level = levelInfo
		}
	}
	return level
}

// extractLinks returns the URLs of the text parts of a mail, HTML parts
// first (what the reader usually sees), in order of appearance, duplicates
// merged.
func extractLinks(mail mailtoolkit.Mail) []Link {
	collector := linkCollector{index: map[string]int{}}
	keys := contentKeys(mail.Contents)
	sort.SliceStable(keys, func(i, j int) bool {
		return mail.Contents[keys[i]].ContentInfo.Type.Subtype == "html" && mail.Contents[keys[j]].ContentInfo.Type.Subtype != "html"
	})
	for _, key := range keys {
		content := mail.Contents[key]
		ct := content.ContentInfo.Type
		if ct.Type != "text" || (ct.Subtype != "html" && ct.Subtype != "plain") {
			continue
		}
		data, err := content.Decode()
		if err != nil {
			continue
		}
		data = toUTF8(data, ct.Parameters["charset"])
		part := ct.Type + "/" + ct.Subtype
		if ct.Subtype == "html" {
			collector.html(data, part)
		} else {
			collector.text(string(data), part)
		}
	}
	return collector.links
}

type linkCollector struct {
	links []Link
	index map[string]int
}

func (c *linkCollector) add(raw, text, source, part string, extra ...LinkWarning) {
	raw = cleanURL(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "cid:") {
		return
	}
	text = collapseSpaces(text)
	key := source + "\x00" + raw + "\x00" + text
	if i, ok := c.index[key]; ok {
		c.links[i].Count++
		return
	}
	link := analyzeLink(raw, text, source, part)
	link.Warnings = append(link.Warnings, extra...)
	c.index[key] = len(c.links)
	c.links = append(c.links, link)
}

// html walks the tokens of an HTML part. The tokenizer splits the markup the
// way browsers do, so obfuscated markup cannot hide a link.
func (c *linkCollector) html(data []byte, part string) {
	z := html.NewTokenizer(bytes.NewReader(data))
	var anchor *anchorState
	var inStyle bool
	for {
		switch z.Next() {
		case html.ErrorToken:
			if anchor != nil {
				c.add(anchor.href, anchor.text.String(), "lien", part)
			}
			return

		case html.TextToken:
			if inStyle {
				c.cssURLs(string(z.Text()), part)
			} else if anchor != nil {
				anchor.text.Write(z.Text())
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.A:
				if anchor != nil {
					c.add(anchor.href, anchor.text.String(), "lien", part)
					anchor = nil
				}
			case atom.Style:
				inStyle = false
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			attrs := attributes(token)
			if style, ok := attrs["style"]; ok {
				c.cssURLs(style, part)
			}
			if background, ok := attrs["background"]; ok {
				c.add(background, "", "image de fond", part)
			}
			switch token.DataAtom {
			case atom.A:
				if href, ok := attrs["href"]; ok {
					if anchor != nil {
						c.add(anchor.href, anchor.text.String(), "lien", part)
					}
					anchor = &anchorState{href: href}
				}
			case atom.Area:
				c.add(attrs["href"], attrs["alt"], "zone d'image", part)
			case atom.Img:
				if anchor != nil {
					anchor.text.WriteString(" [image : " + attrs["alt"] + "] ")
				}
				var extra []LinkWarning
				if attrs["width"] == "1" && attrs["height"] == "1" || attrs["width"] == "0" || attrs["height"] == "0" {
					extra = append(extra, LinkWarning{levelInfo, "Image invisible : probablement un pixel de suivi"})
				}
				c.add(attrs["src"], attrs["alt"], "image", part, extra...)
				for _, candidate := range strings.Split(attrs["srcset"], ",") {
					if fields := strings.Fields(candidate); len(fields) > 0 {
						c.add(fields[0], attrs["alt"], "image", part)
					}
				}
			case atom.Form:
				action := attrs["action"]
				if action == "" {
					action = "(page courante)"
				}
				c.add(action, "", "formulaire", part, LinkWarning{levelDanger, "Formulaire dans un mail : les données saisies sont envoyées à cette adresse"})
			case atom.Iframe, atom.Frame, atom.Embed, atom.Script, atom.Source, atom.Video, atom.Audio:
				c.add(attrs["src"], "", "contenu embarqué ("+token.Data+")", part)
			case atom.Object:
				c.add(attrs["data"], "", "contenu embarqué (object)", part)
			case atom.Link:
				c.add(attrs["href"], "", "ressource ("+attrs["rel"]+")", part)
			case atom.Base:
				c.add(attrs["href"], "", "base des liens relatifs", part,
					LinkWarning{levelWarning, "Balise <base> : modifie la destination de tous les liens relatifs"})
			case atom.Meta:
				if strings.EqualFold(attrs["http-equiv"], "refresh") {
					if _, target, ok := strings.Cut(strings.ToLower(attrs["content"]), "url="); ok {
						start := len(attrs["content"]) - len(target)
						c.add(strings.Trim(attrs["content"][start:], `'" `), "", "redirection automatique", part,
							LinkWarning{levelDanger, "Redirection automatique à l'ouverture"})
					}
				}
			case atom.Style:
				inStyle = token.Type == html.StartTagToken
			}
		}
	}
}

type anchorState struct {
	href string
	text strings.Builder
}

var (
	cssURLRegex  = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")\s]+)['"]?\s*\)`)
	textURLRegex = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+`)
)

func (c *linkCollector) cssURLs(css, part string) {
	for _, m := range cssURLRegex.FindAllStringSubmatch(css, -1) {
		c.add(m[1], "", "style (CSS)", part)
	}
}

// text finds the URLs written in a plain text part; mail clients turn them
// into clickable links.
func (c *linkCollector) text(text, part string) {
	for _, raw := range textURLRegex.FindAllString(text, -1) {
		raw = strings.TrimRight(raw, ".,;:!?")
		if strings.HasPrefix(strings.ToLower(raw), "www.") {
			raw = "http://" + raw
		}
		c.add(raw, "", "texte", part)
	}
}

func attributes(token html.Token) map[string]string {
	attrs := make(map[string]string, len(token.Attr))
	for _, a := range token.Attr {
		if _, exists := attrs[a.Key]; !exists { // browsers keep the first one
			attrs[a.Key] = a.Val
		}
	}
	return attrs
}

// cleanURL removes what browsers ignore in a URL: leading and trailing
// spaces and control characters, tabs and newlines anywhere. Without this,
// "java\tscript:" would not be recognized as javascript:.
func cleanURL(raw string) string {
	raw = strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, raw)
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

var shorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "ow.ly": true, "is.gd": true,
	"buff.ly": true, "rebrand.ly": true, "cutt.ly": true, "shorturl.at": true, "tiny.cc": true,
	"rb.gy": true, "t.ly": true, "s.id": true, "lnkd.in": true, "bl.ink": true, "short.io": true,
}

// analyzeLink parses a URL and lists what may deceive the reader.
func analyzeLink(raw, text, source, part string) Link {
	link := Link{URL: raw, Text: text, Source: source, Part: part, Count: 1}
	warn := func(level, message string) {
		link.Warnings = append(link.Warnings, LinkWarning{level, message})
	}

	u, err := url.Parse(raw)
	if err != nil {
		warn(levelWarning, "URL invalide : les navigateurs peuvent l'interpréter différemment")
		return link
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "https", "mailto", "tel":
	case "http":
		warn(levelInfo, "Connexion non chiffrée (http)")
	case "javascript", "vbscript", "data", "file":
		warn(levelDanger, "Schéma « "+scheme+": » : exécute du code ou ouvre un contenu local")
		return link
	case "":
		if source == "lien" {
			warn(levelInfo, "Lien relatif : sa destination dépend de la page où le mail est affiché")
		}
		return link
	default:
		warn(levelWarning, "Schéma inhabituel « "+scheme+": »")
	}
	if strings.EqualFold(u.Scheme, "mailto") {
		link.Host = strings.SplitN(u.Opaque, "?", 2)[0]
		return link
	}

	host := strings.ToLower(u.Hostname())
	link.Host = displayHost(host)
	if u.User != nil {
		warn(levelDanger, "« "+u.User.Username()+"@ » avant le domaine : la vraie destination est "+link.Host)
	}
	if net.ParseIP(host) != nil {
		warn(levelWarning, "Adresse IP au lieu d'un nom de domaine")
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		warn(levelWarning, "Port inhabituel : "+port)
	}
	if link.Host != host {
		warn(levelWarning, "Nom de domaine internationalisé ("+host+") : vérifiez qu'il n'imite pas un domaine connu")
	}
	if shorteners[strings.TrimPrefix(host, "www.")] {
		warn(levelWarning, "Lien raccourci : la destination réelle est masquée")
	}
	if target := redirectTarget(u); target != "" {
		link.Target = target
		if t, err := url.Parse(target); err == nil {
			warn(levelInfo, "Redirige vers "+displayHost(strings.ToLower(t.Hostname())))
		}
	}
	if shown := displayedHost(text); shown != "" && !sameSite(shown, host) {
		warn(levelDanger, "Le texte affiché mène en apparence à "+displayHost(shown)+", mais le lien pointe vers "+link.Host)
	}
	return link
}

// redirectTarget returns an absolute URL passed as a query parameter, as
// used by redirectors, trackers and Outlook Safe Links.
func redirectTarget(u *url.URL) string {
	for _, values := range u.Query() {
		for _, v := range values {
			lower := strings.ToLower(v)
			if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
				return v
			}
		}
	}
	return ""
}

var domainLike = regexp.MustCompile(`(?i)^(?:https?://)?(?:www\.)?((?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,})(?:[/:?#].*)?$`)

// displayedHost returns the host a link text pretends to lead to, when the
// text looks like a URL or a domain name.
func displayedHost(text string) string {
	text = strings.TrimSpace(text)
	if strings.ContainsAny(text, " @") {
		return ""
	}
	m := domainLike.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	host, err := idna.Lookup.ToASCII(strings.ToLower(m[1]))
	if err != nil {
		return strings.ToLower(m[1])
	}
	return host
}

// sameSite reports whether two hosts are the same or one is a subdomain of
// the other ("www.bank.com" and "bank.com", "mail.bank.com" and "bank.com").
func sameSite(a, b string) bool {
	a, b = strings.TrimPrefix(a, "www."), strings.TrimPrefix(b, "www.")
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// displayHost shows a punycode host (xn--) in Unicode.
func displayHost(host string) string {
	if unicode, err := idna.Display.ToUnicode(host); err == nil {
		return unicode
	}
	return host
}

// toUTF8 converts the Latin-1 family charsets, the most common non UTF-8
// ones in mails, to UTF-8. ISO-8859-15 is read as ISO-8859-1 (8 characters
// differ). Other charsets are returned unchanged.
func toUTF8(data []byte, charset string) []byte {
	charset = strings.ToLower(charset)
	windows := charset == "windows-1252" || charset == "cp1252"
	if !windows && charset != "iso-8859-1" && charset != "latin1" && charset != "iso-8859-15" {
		return data
	}
	b := make([]byte, 0, len(data)+len(data)/8)
	for _, c := range data {
		r := rune(c)
		if windows && c >= 0x80 && c <= 0x9f {
			r = cp1252[c-0x80]
		}
		b = utf8.AppendRune(b, r)
	}
	return b
}

// cp1252 maps the 0x80-0x9F range of windows-1252 (the rest is ISO-8859-1).
var cp1252 = [32]rune{
	'€', 0x81, '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', 0x8d, 'Ž', 0x8f,
	0x90, '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', 0x9d, 'ž', 'Ÿ',
}

// linkGroup gathers the links of one organizational domain.
type linkGroup struct {
	Domain string
	Links  []Link
	// Level is the most severe level of the links.
	Level string
}

// Open tells whether the group is shown unfolded: when it holds a suspect
// link.
func (g linkGroup) Open() bool {
	return g.Level == levelDanger || g.Level == levelWarning
}

// groupLinks groups the links by organizational domain (mail.bank.example
// and www.bank.example together), domains in alphabetical order, links
// without domain last. Inside a group, links are sorted by URL.
func groupLinks(links []Link) []linkGroup {
	index := map[string]int{}
	var groups []linkGroup
	for _, link := range links {
		domain := linkDomain(link)
		i, ok := index[domain]
		if !ok {
			i = len(groups)
			index[domain] = i
			groups = append(groups, linkGroup{Domain: domain})
		}
		g := &groups[i]
		g.Links = append(g.Links, link)
		if level := link.Level(); severity[level] < severity[g.Level] {
			g.Level = level
		}
	}
	for i := range groups {
		sort.SliceStable(groups[i].Links, func(a, b int) bool { return groups[i].Links[a].URL < groups[i].Links[b].URL })
	}
	sort.SliceStable(groups, func(a, b int) bool {
		if (groups[a].Domain == "") != (groups[b].Domain == "") {
			return groups[b].Domain == ""
		}
		return groups[a].Domain < groups[b].Domain
	})
	return groups
}

func linkDomain(link Link) string {
	host := strings.ToLower(link.Host)
	if i := strings.LastIndexByte(host, '@'); i >= 0 { // mailto
		host = host[i+1:]
	}
	if host == "" {
		return ""
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return host
	}
	return mailauth.OrgDomain(host)
}
