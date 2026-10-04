package main

import (
	"crypto/subtle"
	"net/http"
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
}

// admin shows the statistics, behind HTTP basic authentication with the
// admin token. Without token, the page does not exist.
func (s *server) admin(w http.ResponseWriter, r *http.Request) {
	if s.adminToken == "" || s.stats == nil {
		http.NotFound(w, r)
		return
	}
	// After too many failures, even the right token is refused for a
	// while: guessing gets no answer.
	ip := s.clientIP(r)
	if s.adminLimiter.exceeded(ip) {
		http.Error(w, "Trop de tentatives, réessayez plus tard.", http.StatusTooManyRequests)
		return
	}
	_, password, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(s.adminToken)) != 1 {
		if ok {
			s.adminLimiter.allow(ip)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Mail Analyzer admin", charset="UTF-8"`)
		http.Error(w, "Authentification requise.", http.StatusUnauthorized)
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
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "admin.html", struct {
		Title   string
		Period  statsPeriod
		Periods []int
		Active  int
		Chart   statsChart
	}{"Statistiques", period, statsPeriods, s.store.Active(), newStatsChart(period.Daily)})
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
