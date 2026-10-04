package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"strconv"
)

// statsPeriods are the periods the statistics page offers, in days.
var statsPeriods = []int{7, 30, 90, 365}

// reasonNames name the kinds of findings of the statistics.
var reasonNames = map[string]string{
	"dmarc":       "Expéditeur non authentifié ou usurpé",
	"headers":     "En-têtes trompeurs ou nom usurpé",
	"antispam":    "Classé indésirable par l'antispam",
	"links":       "Liens piégés ou suspects",
	"attachments": "Pièces jointes dangereuses",
	"reputation":  "Domaines sosies, listes noires, domaines récents",
	"smime":       "Signature S/MIME douteuse",
	"fraud":       "Demande de paiement ou d'identifiants (fraude)",
	"qrcodes":     "QR codes",
	"threats":     "Connu des bases de menaces",
	"lists":       "Sur la liste noire locale",
}

// authorized checks the HTTP basic authentication of the statistics page,
// or writes the error response. Without token, the page does not exist.
func (s *server) authorized(w http.ResponseWriter, r *http.Request) bool {
	if s.adminToken == "" || s.stats == nil {
		http.NotFound(w, r)
		return false
	}
	// After too many failures, even the right token is refused for a
	// while: guessing gets no answer.
	ip := s.clientIP(r)
	if s.adminLimiter.exceeded(ip) {
		httpError(w, r, "Trop de tentatives, réessayez plus tard.", http.StatusTooManyRequests)
		return false
	}
	_, password, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(s.adminToken)) != 1 {
		if ok {
			s.adminLimiter.allow(ip)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Mail Analyzer admin", charset="UTF-8"`)
		httpError(w, r, "Authentification requise.", http.StatusUnauthorized)
		return false
	}
	return true
}

// csrfToken protects the forms of the statistics page: the browser sends
// the basic authentication with any request, a form posted from another
// site included.
func (s *server) csrfToken() string {
	mac := hmac.New(sha256.New, []byte(s.adminToken))
	mac.Write([]byte("admin forms"))
	return hex.EncodeToString(mac.Sum(nil))
}

// admin shows the statistics and the local lists.
func (s *server) admin(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if !slices.Contains(statsPeriods, days) || err != nil {
		days = 30
	}
	period := s.stats.period(days)
	for i := range period.Reasons {
		if name, ok := reasonNames[period.Reasons[i].Key]; ok {
			period.Reasons[i].Key = name
		}
	}
	entries := s.lists.all()
	// Domains already listed are not suggested again.
	period.Suggestions = slices.DeleteFunc(period.Suggestions, func(c statsCount) bool {
		return slices.ContainsFunc(entries, func(e listEntry) bool { return e.Kind == listDomain && e.Value == c.Key })
	})
	if len(period.Suggestions) > 15 {
		period.Suggestions = period.Suggestions[:15]
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "admin.html", struct {
		Title   string
		Period  statsPeriod
		Periods []int
		Active  int
		Chart   statsChart
		Lists   []listEntry
		CSRF    string
		Error   string
	}{"Statistiques", period, statsPeriods, s.store.Active(), newStatsChart(period.Daily), entries, s.csrfToken(),
		r.URL.Query().Get("error")})
}

// adminLists adds (action=add) or removes (action=delete) an entry of the
// local lists.
func (s *server) adminLists(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if s.lists == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrfToken())) != 1 {
		httpError(w, r, "Formulaire expiré ou envoyé depuis un autre site.", http.StatusForbidden)
		return
	}
	var err error
	switch r.PostFormValue("action") {
	case "add":
		err = s.lists.add(r.PostFormValue("kind"), r.PostFormValue("value"), r.PostFormValue("verdict"), r.PostFormValue("note"))
	case "delete":
		err = s.lists.remove(r.PostFormValue("kind"), r.PostFormValue("value"))
	default:
		httpError(w, r, "Action inconnue.", http.StatusBadRequest)
		return
	}
	target := "/admin?days=" + url.QueryEscape(r.PostFormValue("days"))
	if err != nil {
		target += "&error=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, target+"#lists", http.StatusSeeOther)
}

// statsChart is the daily chart of the analyses, drawn as SVG by the
// template (the page loads no script).
type statsChart struct {
	Width, Height int
	Bars          []statsBar
	Max           int
	// Labels are the dates written under the chart.
	Labels []statsLabel
}

type statsBar struct {
	Date     string
	X, Width int
	Total    int
	Segments []statsSegment
}

// statsSegment is the part of a bar for one light.
type statsSegment struct {
	Class     string
	Y, Height int
}

type statsLabel struct {
	X    int
	Text string
}

const chartHeight = 160

func newStatsChart(days []statsDay) statsChart {
	c := statsChart{Width: 720, Height: chartHeight}
	for _, d := range days {
		c.Max = max(c.Max, d.Total())
	}
	if c.Max == 0 || len(days) == 0 {
		return c
	}
	slot := float64(c.Width) / float64(len(days))
	width := max(1, int(slot*0.75))
	for i, d := range days {
		bar := statsBar{Date: d.Date, X: int(float64(i) * slot), Width: width, Total: d.Total()}
		y := chartHeight
		for _, seg := range []struct {
			n     int
			class string
		}{{d.Green, "bar-green"}, {d.Orange, "bar-orange"}, {d.Red, "bar-red"}, {d.Others, "bar-other"}} {
			if h := seg.n * chartHeight / c.Max; h > 0 {
				y -= h
				bar.Segments = append(bar.Segments, statsSegment{Class: seg.class, Y: y, Height: h})
			}
		}
		c.Bars = append(c.Bars, bar)
	}
	step := max(1, (len(days)+5)/6)
	for i := 0; i < len(days); i += step {
		c.Labels = append(c.Labels, statsLabel{X: int(float64(i) * slot), Text: days[i].Date[5:]})
	}
	return c
}
