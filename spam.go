package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// spamReport is the verdict of an antispam filter, read from the headers it
// added to the mail.
type spamReport struct {
	Filter  string
	Fields  []fieldRef
	Verdict string
	Level   string
	Score   string
	Items   []spamItem
	Rules   []spamRule
	// Trusted is set when the headers were added by a receiving server:
	// the sender can write any header in its mail.
	Trusted bool
	// Outbound is set for the report of the sender's own filter.
	Outbound bool
}

type fieldRef struct {
	Index int
	Name  string
}

// spamItem is a decoded value of a report.
type spamItem struct {
	Name    string
	Value   string
	Meaning string
	Level   string
}

// spamRule is a test or symbol that matched, with its weight.
type spamRule struct {
	Name     string
	Score    float64
	HasScore bool
	Detail   string
}

// ScoreText formats the weight of a rule.
func (r spamRule) ScoreText() string {
	if !r.HasScore {
		return ""
	}
	return strconv.FormatFloat(r.Score, 'f', -1, 64)
}

// Level colors the rules raising the score.
func (r spamRule) Level() string {
	switch {
	case r.Score >= 2:
		return levelDanger
	case r.Score > 0:
		return levelWarning
	case r.Score < 0:
		return "ok"
	}
	return ""
}

// spamPrefixes are the header fields read by the filters below; the other
// fields whose name mentions spam, phishing or viruses are listed as is.
var spamPrefixes = []string{"x-forefront-antispam", "x-microsoft-antispam", "x-ms-exchange-organization-scl",
	"x-spam", "x-rspamd", "x-proofpoint-", "x-mimecast-", "x-barracuda-", "x-ironport-", "x-gm-spam", "x-gm-phishy",
	"x-pm-spam", "x-virus", "x-antivirus", "x-amavis"}

var spamWords = regexp.MustCompile(`(?i)spam|phish|virus|malware`)

// isSpamField reports whether a header field belongs to an antispam or
// antivirus filter.
func isSpamField(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range spamPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return strings.HasPrefix(name, "x-") && spamWords.MatchString(name)
}

// spamContext tells which header fields were written by a receiving server.
type spamContext struct {
	m mailauth.Message
	// sourceField is the Received field of the reception from the sender's
	// server, -1 when unknown: fields above it were added after.
	sourceField int
	receivers   map[string]bool
	used        map[int]bool
}

func newSpamContext(m mailauth.Message, source int, receivers map[string]bool) *spamContext {
	c := &spamContext{m: m, sourceField: -1, receivers: receivers, used: map[int]bool{}}
	var received []int
	for i, f := range m.Fields {
		if strings.EqualFold(f.Name, "Received") {
			received = append(received, i)
		}
	}
	// Hops are listed oldest first, the Received fields newest first.
	if source >= 0 && source < len(received) {
		c.sourceField = received[len(received)-1-source]
	}
	return c
}

// field returns the topmost field called name not read yet.
func (c *spamContext) field(name string) (mailauth.Field, int, bool) {
	for i, f := range c.m.Fields {
		if !c.used[i] && strings.EqualFold(f.Name, name) {
			c.used[i] = true
			return f, i, true
		}
	}
	return mailauth.Field{}, -1, false
}

// trusted reports whether a field was added by a receiving server: above
// the reception from the sender, or written by a receiving provider (Exchange
// moves its fields below the Received ones).
func (c *spamContext) trusted(index int, provider string) bool {
	return (c.sourceField >= 0 && index < c.sourceField) || (provider != "" && c.receivers[provider])
}

// spamReports reads the verdicts of the antispam filters the mail went
// through.
func spamReports(m mailauth.Message, source int, receivers map[string]bool) []spamReport {
	c := newSpamContext(m, source, receivers)
	var reports []spamReport
	for _, read := range []func(*spamContext) (spamReport, bool){microsoftReport, rspamdReport, spamAssassinReport,
		proofpointReport, gmailReport, barracudaReport, mimecastReport, otherSpamFields} {
		if r, ok := read(c); ok {
			reports = append(reports, r)
		}
	}
	return reports
}

// spamSeverity orders the levels of the reports.
var spamSeverity = map[string]int{levelDanger: 3, levelWarning: 2, "ok": 1, levelInfo: 0, "": 0}

// SpamVerdict summarizes the reports for the verdict banner: the worst
// trusted inbound report.
func (a headerAnalysis) SpamVerdict() authVerdict {
	v := authVerdict{Name: "Antispam", Level: levelInfo, Result: "aucun", Source: "aucun en-tête de filtrage"}
	found := false
	for _, r := range a.Spam {
		if !r.Trusted || r.Outbound || r.Level == "" {
			continue
		}
		if !found || spamSeverity[r.Level] > spamSeverity[v.Level] {
			v.Level, v.Result, v.Source = r.Level, r.Verdict, r.Filter
			found = true
		}
	}
	if !found && len(a.Spam) > 0 {
		v.Result, v.Source = "non vérifiable", "en-têtes ajoutés avant la réception"
	}
	return v
}

// Microsoft 365, Exchange Online Protection
// https://learn.microsoft.com/defender-office-365/message-headers-eop-mdo

var microsoftCategories = map[string][2]string{
	"NONE":   {"aucune catégorie", "ok"},
	"BULK":   {"envoi en nombre (newsletter, publicité)", levelInfo},
	"SPM":    {"spam", levelWarning},
	"HSPM":   {"spam avec un niveau de confiance élevé", levelDanger},
	"PHSH":   {"phishing", levelDanger},
	"HPHSH":  {"phishing avec un niveau de confiance élevé", levelDanger},
	"HPHISH": {"phishing avec un niveau de confiance élevé", levelDanger},
	"MALW":   {"logiciel malveillant", levelDanger},
	"AMP":    {"bloqué par l'antimalware", levelDanger},
	"SAP":    {"pièce jointe dangereuse (Safe Attachments)", levelDanger},
	"FTBP":   {"type de pièce jointe bloqué", levelDanger},
	"SPOOF":  {"usurpation de l'expéditeur (spoofing)", levelDanger},
	"DIMP":   {"usurpation d'un domaine", levelDanger},
	"UIMP":   {"usurpation d'une personne", levelDanger},
	"GIMP":   {"usurpation détectée par l'analyse des contacts", levelDanger},
	"BIMP":   {"usurpation d'une marque", levelDanger},
	"INTOS":  {"phishing interne à l'organisation", levelDanger},
	"OSPM":   {"spam sortant", levelWarning},
}

var microsoftFilterVerdicts = map[string][2]string{
	"NSPM": {"pas de spam", "ok"},
	"SPM":  {"spam", levelWarning},
	"SFE":  {"filtrage ignoré : expéditeur dans les expéditeurs approuvés de l'utilisateur", levelWarning},
	"SKA":  {"filtrage ignoré : expéditeur autorisé par la politique", levelWarning},
	"SKB":  {"spam : expéditeur bloqué par la politique", levelWarning},
	"SKI":  {"filtrage ignoré : mail interne à l'organisation", levelInfo},
	"SKN":  {"marqué non-spam par une règle de flux de messagerie", levelWarning},
	"SKS":  {"marqué spam par une règle de flux de messagerie", levelWarning},
	"SKQ":  {"libéré de la quarantaine", levelWarning},
	"BLK":  {"expéditeur bloqué par l'utilisateur", levelWarning},
}

func microsoftReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Microsoft 365 (Exchange Online Protection)"}
	trusted := true
	add := func(name string) (mailauth.Field, bool) {
		f, i, ok := c.field(name)
		if !ok {
			// Exchange renames the fields received from outside.
			if f, i, ok = c.field(name + "-Untrusted"); ok {
				trusted = false
			}
		}
		if ok {
			r.Fields = append(r.Fields, fieldRef{i, f.Name})
			trusted = trusted && c.trusted(i, "microsoft")
		}
		return f, ok
	}

	report, hasReport := add("X-Forefront-Antispam-Report")
	antispam, hasAntispam := add("X-Microsoft-Antispam")
	delivery, hasDelivery := add("X-Microsoft-Antispam-Mailbox-Delivery")
	orgSCL, hasOrgSCL := add("X-MS-Exchange-Organization-SCL")
	if !hasReport && !hasAntispam && !hasDelivery && !hasOrgSCL {
		return r, false
	}
	r.Trusted = trusted

	values := colonPairs(report.Value)
	scl, err := strconv.Atoi(values["SCL"])
	hasSCL := err == nil
	if !hasSCL && hasOrgSCL {
		scl, err = strconv.Atoi(strings.TrimSpace(orgSCL.Value))
		hasSCL = err == nil
	}

	if dir := values["DIR"]; dir != "" {
		meaning := map[string]string{"INB": "entrant", "OUT": "sortant : analyse faite chez l'expéditeur", "INT": "interne à l'organisation"}[dir]
		r.Items = append(r.Items, spamItem{"DIR", dir, meaning, ""})
		r.Outbound = dir == "OUT"
	}
	if hasSCL {
		meaning, level := sclMeaning(scl)
		r.Items = append(r.Items, spamItem{"SCL", strconv.Itoa(scl), meaning, level})
		r.Score = "SCL " + strconv.Itoa(scl)
	}
	if sfv := values["SFV"]; sfv != "" {
		d := microsoftFilterVerdicts[sfv]
		r.Items = append(r.Items, spamItem{"SFV", sfv, d[0], d[1]})
	}
	category := values["CAT"]
	if category != "" {
		d, ok := microsoftCategories[category]
		if !ok {
			d = [2]string{"catégorie inconnue", levelInfo}
		}
		r.Items = append(r.Items, spamItem{"CAT", category, d[0], d[1]})
	}
	if bcl, err := strconv.Atoi(colonPairs(antispam.Value)["BCL"]); err == nil {
		meaning, level := bclMeaning(bcl)
		r.Items = append(r.Items, spamItem{"BCL", strconv.Itoa(bcl), meaning, level})
	}
	if hasDelivery {
		d := colonPairs(delivery.Value)
		switch dest := d["dest"]; dest {
		case "I":
			r.Items = append(r.Items, spamItem{"dest", dest, "livré dans la boîte de réception", "ok"})
		case "J":
			r.Items = append(r.Items, spamItem{"dest", dest, "livré dans le courrier indésirable", levelWarning})
		case "":
		default:
			r.Items = append(r.Items, spamItem{"dest", dest, "livré dans un autre dossier", levelInfo})
		}
		if ofr := d["OFR"]; ofr != "" {
			r.Items = append(r.Items, spamItem{"OFR", ofr, "raison du classement dans le dossier", ""})
		}
	}
	for _, key := range []string{"CIP", "CTRY", "LANG", "IPV", "H", "PTR", "SRV", "SFTY"} {
		value := values[key]
		if value == "" {
			continue
		}
		meaning := map[string]string{
			"CIP": "IP du serveur d'envoi", "CTRY": "pays de cette IP", "LANG": "langue du mail", "H": "nom annoncé (HELO)",
			"PTR": "nom DNS inverse de l'IP", "SRV": "service", "SFTY": "conseil de sécurité (usurpation, premier contact…)",
		}[key]
		if key == "IPV" {
			meaning = map[string]string{"CAL": "IP dans la liste d'autorisation", "NLI": "IP absente des listes de réputation"}[value]
		}
		r.Items = append(r.Items, spamItem{key, value, meaning, ""})
	}

	switch {
	case microsoftCategories[category][1] == levelDanger:
		r.Verdict, r.Level = microsoftCategories[category][0], levelDanger
	case hasSCL && scl >= 5, values["SFV"] == "SPM", category == "SPM":
		r.Verdict, r.Level = "spam", levelWarning
	case hasSCL && scl == -1:
		r.Verdict, r.Level = "filtrage contourné", levelWarning
	case category == "BULK":
		r.Verdict, r.Level = "envoi en nombre", levelInfo
	case hasSCL || values["SFV"] == "NSPM":
		r.Verdict, r.Level = "pas de spam", "ok"
	default:
		r.Verdict = "voir les détails"
	}
	return r, true
}

func sclMeaning(scl int) (string, string) {
	switch {
	case scl < 0:
		return "filtrage contourné : expéditeur ou serveur considéré comme sûr", levelWarning
	case scl <= 4:
		return "pas du spam", "ok"
	case scl <= 6:
		return "spam", levelWarning
	}
	return "spam avec un niveau de confiance élevé", levelDanger
}

func bclMeaning(bcl int) (string, string) {
	switch {
	case bcl == 0:
		return "pas un envoi en nombre", "ok"
	case bcl <= 3:
		return "envoi en nombre, expéditeur avec peu de plaintes", levelInfo
	case bcl <= 7:
		return "envoi en nombre, plaintes modérées", levelInfo
	}
	return "envoi en nombre, nombreuses plaintes", levelWarning
}

// colonPairs parses "KEY:value;KEY:value" lists.
func colonPairs(s string) map[string]string {
	pairs := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		if key, value, ok := strings.Cut(strings.TrimSpace(part), ":"); ok {
			if _, dup := pairs[key]; !dup {
				pairs[key] = strings.TrimSpace(value)
			}
		}
	}
	return pairs
}

// Rspamd: "default: False [3.40 / 15.00]; SYMBOL(0.50)[options]; ..."

var (
	rspamdHead   = regexp.MustCompile(`^\s*[\w-]+:\s*(True|False)\s*\[\s*(-?[\d.]+)\s*/\s*(-?[\d.]+)\s*\]`)
	rspamdSymbol = regexp.MustCompile(`([A-Z0-9_]+)\((-?[\d.]+)\)(?:\[([^\]]*)\])?`)
)

func rspamdReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Rspamd", Trusted: true}
	result, ri, hasResult := c.field("X-Spamd-Result")
	action, ai, hasAction := c.field("X-Rspamd-Action")
	if !hasResult && !hasAction {
		return r, false
	}
	for _, f := range []struct {
		field mailauth.Field
		index int
		ok    bool
	}{{result, ri, hasResult}, {action, ai, hasAction}} {
		if f.ok {
			r.Fields = append(r.Fields, fieldRef{f.index, f.field.Name})
			r.Trusted = r.Trusted && c.trusted(f.index, "")
		}
	}
	for _, name := range []string{"X-Rspamd-Score", "X-Spamd-Bar", "X-Rspamd-Server", "X-Rspamd-Queue-Id"} {
		if f, i, ok := c.field(name); ok {
			r.Fields = append(r.Fields, fieldRef{i, f.Name})
		}
	}

	spam := false
	if m := rspamdHead.FindStringSubmatch(result.Value); m != nil {
		spam = m[1] == "True"
		r.Score = m[2] + " / " + m[3]
		r.Items = append(r.Items, spamItem{"score", r.Score, "score obtenu / seuil de rejet", ""})
	}
	for _, m := range rspamdSymbol.FindAllStringSubmatch(result.Value, -1) {
		score, err := strconv.ParseFloat(m[2], 64)
		r.Rules = append(r.Rules, spamRule{Name: m[1], Score: score, HasScore: err == nil, Detail: m[3]})
	}
	sortRules(r.Rules)

	a := strings.ToLower(strings.TrimSpace(action.Value))
	if hasAction {
		r.Items = append(r.Items, spamItem{"action", a, rspamdActions[a], ""})
	}
	switch {
	case a == "reject" || a == "add header" || a == "rewrite subject" || spam:
		r.Verdict, r.Level = "spam", levelWarning
	case a == "greylist" || a == "soft reject":
		r.Verdict, r.Level = "suspect (mise en attente)", levelInfo
	default:
		r.Verdict, r.Level = "pas de spam", "ok"
	}
	return r, true
}

var rspamdActions = map[string]string{
	"no action":       "aucune action : pas de spam",
	"greylist":        "mise en attente temporaire",
	"soft reject":     "refus temporaire",
	"add header":      "marqué comme spam",
	"rewrite subject": "sujet modifié : spam",
	"reject":          "refusé : spam",
}

// SpamAssassin: "Yes, score=7.2 required=5.0 tests=BAYES_99,URIBL_BLACK=1.7 autolearn=no version=3.4.6"

var spamAssassinKey = regexp.MustCompile(`\b(score|hits|required|tests|autolearn|autolearn_force|version)=`)

func spamAssassinReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Filtre antispam (X-Spam-Status)", Trusted: true}
	status, si, hasStatus := c.field("X-Spam-Status")
	flag, fi, hasFlag := c.field("X-Spam-Flag")
	score, sci, hasScore := c.field("X-Spam-Score")
	if !hasStatus && !hasFlag && !hasScore {
		return r, false
	}
	for _, f := range []struct {
		field mailauth.Field
		index int
		ok    bool
	}{{status, si, hasStatus}, {flag, fi, hasFlag}, {score, sci, hasScore}} {
		if f.ok {
			r.Fields = append(r.Fields, fieldRef{f.index, f.field.Name})
			r.Trusted = r.Trusted && c.trusted(f.index, "")
		}
	}
	for _, name := range []string{"X-Spam-Level", "X-Spam-Checker-Version", "X-Spam-Report"} {
		if f, i, ok := c.field(name); ok {
			r.Fields = append(r.Fields, fieldRef{i, f.Name})
			if strings.Contains(f.Value, "SpamAssassin") {
				r.Filter = "SpamAssassin"
			}
		}
	}

	values := map[string]string{}
	locations := spamAssassinKey.FindAllStringSubmatchIndex(status.Value, -1)
	for i, loc := range locations {
		end := len(status.Value)
		if i+1 < len(locations) {
			end = locations[i+1][0]
		}
		values[status.Value[loc[2]:loc[3]]] = strings.TrimSpace(status.Value[loc[1]:end])
	}
	if values["score"] == "" {
		values["score"] = values["hits"]
	}
	if values["score"] == "" && hasScore {
		values["score"] = strings.TrimSpace(score.Value)
	}
	if values["score"] != "" {
		r.Score = values["score"]
		if values["required"] != "" {
			r.Score += " / " + values["required"]
		}
		r.Items = append(r.Items, spamItem{"score", r.Score, "score obtenu / seuil du spam", ""})
	}
	if values["tests"] != "" && values["tests"] != "none" {
		for _, test := range strings.Split(strings.Join(strings.Fields(values["tests"]), ""), ",") {
			name, weight, hasWeight := strings.Cut(test, "=")
			rule := spamRule{Name: name}
			if hasWeight {
				rule.Score, _ = strconv.ParseFloat(weight, 64)
				rule.HasScore = true
			}
			if name != "" {
				r.Rules = append(r.Rules, rule)
			}
		}
		sortRules(r.Rules)
	}
	if values["tests"] != "" {
		r.Filter = "SpamAssassin"
	}

	answer := strings.ToLower(firstToken(status.Value))
	if answer == "" && hasFlag {
		answer = strings.ToLower(strings.TrimSpace(flag.Value))
	}
	switch answer {
	case "yes":
		r.Verdict, r.Level = "spam", levelWarning
	case "no":
		r.Verdict, r.Level = "pas de spam", "ok"
	default:
		r.Verdict, r.Level = "voir les détails", levelInfo
	}
	return r, true
}

// Proofpoint: "rule=notspam policy=default score=0 spamscore=0 phishscore=0 ..."

func proofpointReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Proofpoint"}
	details, i, ok := c.field("X-Proofpoint-Spam-Details")
	if !ok {
		return r, false
	}
	r.Fields = append(r.Fields, fieldRef{i, details.Name})
	r.Trusted = c.trusted(i, "")
	for _, name := range []string{"X-Proofpoint-Virus-Version", "X-Proofpoint-GUID", "X-Proofpoint-ORIG-GUID", "X-Proofpoint-Spam-Reason"} {
		if f, j, ok := c.field(name); ok {
			r.Fields = append(r.Fields, fieldRef{j, f.Name})
		}
	}
	values := map[string]string{}
	for _, word := range strings.Fields(details.Value) {
		if key, value, ok := strings.Cut(word, "="); ok {
			values[key] = value
		}
	}
	meanings := map[string]string{"rule": "règle appliquée", "spamscore": "score de spam (0 à 100)", "phishscore": "score de phishing (0 à 100)",
		"malwarescore": "score de logiciel malveillant (0 à 100)", "bulkscore": "score d'envoi en nombre (0 à 100)",
		"suspectscore": "score de suspicion (0 à 100)", "adultscore": "score de contenu pour adultes (0 à 100)"}
	for _, key := range []string{"rule", "spamscore", "phishscore", "malwarescore", "suspectscore", "bulkscore", "adultscore"} {
		if value, ok := values[key]; ok {
			level := ""
			if n, err := strconv.Atoi(value); err == nil && n >= 50 {
				level = levelWarning
			}
			r.Items = append(r.Items, spamItem{key, value, meanings[key], level})
		}
	}
	r.Score = values["spamscore"]
	rule := strings.ToLower(values["rule"])
	switch {
	case strings.Contains(rule, "notspam"), strings.Contains(rule, "inbound_notspam"):
		r.Verdict, r.Level = "pas de spam", "ok"
	case strings.Contains(rule, "phish"), strings.Contains(rule, "malware"):
		r.Verdict, r.Level = rule, levelDanger
	case strings.Contains(rule, "spam"):
		r.Verdict, r.Level = "spam", levelWarning
	case strings.Contains(rule, "bulk"):
		r.Verdict, r.Level = "envoi en nombre", levelInfo
	default:
		r.Verdict, r.Level = "voir les détails", levelInfo
	}
	return r, true
}

// Gmail: X-Gm-Spam and X-Gm-Phishy, 0 or 1.

func gmailReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Gmail", Trusted: true}
	spam, si, hasSpam := c.field("X-Gm-Spam")
	phishy, pi, hasPhishy := c.field("X-Gm-Phishy")
	if !hasSpam && !hasPhishy {
		return r, false
	}
	if hasSpam {
		r.Fields = append(r.Fields, fieldRef{si, spam.Name})
		r.Trusted = r.Trusted && c.trusted(si, "google")
		r.Items = append(r.Items, spamItem{"X-Gm-Spam", spam.Value, map[string]string{"0": "pas de spam", "1": "spam"}[spam.Value], ""})
	}
	if hasPhishy {
		r.Fields = append(r.Fields, fieldRef{pi, phishy.Name})
		r.Trusted = r.Trusted && c.trusted(pi, "google")
		r.Items = append(r.Items, spamItem{"X-Gm-Phishy", phishy.Value, map[string]string{"0": "pas de suspicion de phishing", "1": "suspicion de phishing"}[phishy.Value], ""})
	}
	switch {
	case phishy.Value == "1":
		r.Verdict, r.Level = "suspicion de phishing", levelDanger
	case spam.Value == "1":
		r.Verdict, r.Level = "spam", levelWarning
	default:
		r.Verdict, r.Level = "pas de spam", "ok"
	}
	return r, true
}

// Barracuda: X-Barracuda-Spam-Status "No, SCORE=0.00 using ... QUARANTINE_LEVEL=..."

var barracudaScore = regexp.MustCompile(`SCORE=(-?[\d.]+)`)

func barracudaReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Barracuda", Trusted: true}
	status, i, ok := c.field("X-Barracuda-Spam-Status")
	if !ok {
		return r, false
	}
	r.Fields = append(r.Fields, fieldRef{i, status.Name})
	r.Trusted = c.trusted(i, "")
	for _, name := range []string{"X-Barracuda-Spam-Score", "X-Barracuda-Spam-Report", "X-Barracuda-Connect", "X-Barracuda-URL"} {
		if f, j, ok := c.field(name); ok {
			r.Fields = append(r.Fields, fieldRef{j, f.Name})
		}
	}
	if m := barracudaScore.FindStringSubmatch(status.Value); m != nil {
		r.Score = m[1]
		r.Items = append(r.Items, spamItem{"score", m[1], "score de spam", ""})
	}
	if strings.EqualFold(firstToken(status.Value), "yes") {
		r.Verdict, r.Level = "spam", levelWarning
	} else {
		r.Verdict, r.Level = "pas de spam", "ok"
	}
	return r, true
}

// Mimecast: X-Mimecast-Spam-Score, a number.

func mimecastReport(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Mimecast"}
	score, i, ok := c.field("X-Mimecast-Spam-Score")
	if !ok {
		return r, false
	}
	r.Fields = append(r.Fields, fieldRef{i, score.Name})
	r.Trusted = c.trusted(i, "")
	for _, name := range []string{"X-Mimecast-Spam-Signature", "X-Mimecast-MFC-PROC-ID", "X-Mimecast-Impersonation-Protect"} {
		if f, j, ok := c.field(name); ok {
			r.Fields = append(r.Fields, fieldRef{j, f.Name})
			r.Items = append(r.Items, spamItem{f.Name, f.Value, "", ""})
		}
	}
	r.Score = strings.TrimSpace(score.Value)
	r.Items = append([]spamItem{{"score", r.Score, "score de spam, plus il est élevé plus le mail est suspect", ""}}, r.Items...)
	r.Verdict, r.Level = "score "+r.Score, levelInfo
	return r, true
}

// otherSpamFields lists the remaining filtering fields as they are.
func otherSpamFields(c *spamContext) (spamReport, bool) {
	r := spamReport{Filter: "Autres en-têtes de filtrage", Verdict: "à titre d'information", Trusted: true}
	for i, f := range c.m.Fields {
		if c.used[i] || !isSpamField(f.Name) {
			continue
		}
		c.used[i] = true
		r.Fields = append(r.Fields, fieldRef{i, f.Name})
		r.Trusted = r.Trusted && c.trusted(i, "")
		r.Items = append(r.Items, spamItem{f.Name, f.Value, "", ""})
	}
	if len(r.Fields) == 0 {
		return r, false
	}
	return r, true
}

// sortRules puts the rules weighing the most first.
func sortRules(rules []spamRule) {
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Score > rules[j].Score })
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " ,;\t"); i >= 0 {
		return s[:i]
	}
	return s
}
