package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"maps"
	"os"
	"slices"
	"sync"
	"time"
)

// Statistics keep aggregated counters per day, never the content, the
// addresses or the subjects of the mails.
const (
	statsFile = "stats.json"
	// statsDays is the number of days kept.
	statsDays = 400
	// maxStatsKeys bounds the brands and domains counted per day.
	maxStatsKeys = 200
	// recordedFor is how long an analyzed mail is remembered, so that it
	// is counted once however often its page is displayed.
	recordedFor = 35 * 24 * time.Hour
)

// dayStats are the counters of one day.
type dayStats struct {
	// Submissions by mode: mx, submission, smtps, ingest, upload.
	Submissions map[string]int `json:"submissions,omitempty"`
	// Mails extracted from the submissions.
	Mails    int `json:"mails"`
	Analyses int `json:"analyses"`
	// Lights counts the analyses by traffic light.
	Lights map[string]int `json:"lights,omitempty"`
	// Reasons counts the analyses by kind of finding (anchor of the
	// detailed view: dmarc, links, attachments, fraud, qrcodes...).
	Reasons map[string]int `json:"reasons,omitempty"`
	// Brands counts the brands imitated, Domains the lookalike and
	// blocklisted domains.
	Brands  map[string]int `json:"brands,omitempty"`
	Domains map[string]int `json:"domains,omitempty"`
	// QRCodes counts the analyses holding a QR code with a link.
	QRCodes int `json:"qr_codes,omitempty"`
}

type statsData struct {
	Days map[string]*dayStats `json:"days"`
	// Recorded are the hashed keys of the analyzed mails, with the time
	// they were counted.
	Recorded map[string]time.Time `json:"recorded"`
}

// statsStore keeps the statistics in the data folder. It is safe for
// concurrent use.
type statsStore struct {
	root *os.Root
	now  func() time.Time

	mu   sync.Mutex
	data statsData
}

func newStatsStore(folder string, now func() time.Time) (*statsStore, error) {
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return nil, err
	}
	s := &statsStore{root: root, now: now, data: statsData{Days: map[string]*dayStats{}, Recorded: map[string]time.Time{}}}
	raw, err := root.ReadFile(statsFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.data); err != nil {
			log.Printf("statistics: %s unreadable, starting again: %v", statsFile, err)
			s.data = statsData{}
		}
		if s.data.Days == nil {
			s.data.Days = map[string]*dayStats{}
		}
		if s.data.Recorded == nil {
			s.data.Recorded = map[string]time.Time{}
		}
	}
	return s, nil
}

// today returns the counters of the current day (UTC); the lock is held.
func (s *statsStore) today() *dayStats {
	key := s.now().UTC().Format(time.DateOnly)
	d := s.data.Days[key]
	if d == nil {
		d = &dayStats{}
		s.data.Days[key] = d
	}
	return d
}

// recordSubmission counts a received mail or an uploaded file.
func (s *statsStore) recordSubmission(mode string, mails int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.today()
	increment(&d.Submissions, mode)
	d.Mails += mails
	s.save()
}

// recordAnalysis counts the analysis of a mail, once per mail.
func (s *statsStore) recordAnalysis(mailKey string, risk riskReport, lookalikes []lookalike, rep reputation, codes []qrCode) {
	if s == nil {
		return
	}
	sum := sha256.Sum256([]byte(mailKey))
	key := hex.EncodeToString(sum[:12])
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, done := s.data.Recorded[key]; done {
		return
	}
	s.data.Recorded[key] = s.now().UTC()
	d := s.today()
	d.Analyses++
	increment(&d.Lights, risk.Light)
	kinds := map[string]bool{}
	for _, r := range risk.Reasons {
		if r.Weight > 0 && r.Anchor != "" {
			kinds[r.Anchor] = true
		}
	}
	for kind := range kinds {
		increment(&d.Reasons, kind)
	}
	brands, domains := map[string]bool{}, map[string]bool{}
	for _, l := range lookalikes {
		brands[l.Brand], domains[l.Domain] = true, true
	}
	for _, l := range rep.Listings {
		if l.Level == levelDanger {
			domains[l.Subject] = true
		}
	}
	for b := range brands {
		increment(&d.Brands, b)
	}
	for domain := range domains {
		increment(&d.Domains, domain)
	}
	for _, c := range codes {
		if c.Link != nil {
			d.QRCodes++
			break
		}
	}
	s.save()
}

// increment adds one to a counter, up to maxStatsKeys keys.
func increment(m *map[string]int, key string) {
	if key == "" {
		return
	}
	if *m == nil {
		*m = map[string]int{}
	}
	if _, ok := (*m)[key]; ok || len(*m) < maxStatsKeys {
		(*m)[key]++
	}
}

// prune forgets the old days and mails; the lock is held.
func (s *statsStore) prune() {
	now := s.now().UTC()
	oldest := now.AddDate(0, 0, -statsDays).Format(time.DateOnly)
	for day := range s.data.Days {
		if day < oldest {
			delete(s.data.Days, day)
		}
	}
	for key, t := range s.data.Recorded {
		if now.Sub(t) > recordedFor {
			delete(s.data.Recorded, key)
		}
	}
}

// save writes the statistics atomically; the lock is held.
func (s *statsStore) save() {
	s.prune()
	raw, err := json.Marshal(s.data)
	if err != nil {
		log.Printf("statistics: %v", err)
		return
	}
	tmp := statsFile + ".tmp"
	if err := s.root.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("statistics: %v", err)
		return
	}
	if err := s.root.Rename(tmp, statsFile); err != nil {
		log.Printf("statistics: %v", err)
	}
}

// statsPeriod sums the counters of the last days.
type statsPeriod struct {
	Days        int
	From, To    string
	Submissions map[string]int
	Received    int
	Uploaded    int
	Mails       int
	Analyses    int
	Lights      map[string]int
	QRCodes     int
	Reasons     []statsCount
	Brands      []statsCount
	Domains     []statsCount
	// Daily are the analyses per day, oldest first.
	Daily []statsDay
}

type statsCount struct {
	Key   string
	Count int
	// Percent is relative to the largest count, for the bars.
	Percent int
}

type statsDay struct {
	Date                       string
	Green, Orange, Red, Others int
	Submissions                int
}

// Total is the number of analyses of the day.
func (d statsDay) Total() int {
	return d.Green + d.Orange + d.Red + d.Others
}

// Percent returns the share of a light among the analyses.
func (p statsPeriod) Percent(light string) int {
	if p.Analyses == 0 {
		return 0
	}
	return (p.Lights[light]*100 + p.Analyses/2) / p.Analyses
}

// period sums the last days, today included.
func (s *statsStore) period(days int) statsPeriod {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := statsPeriod{Days: days, Submissions: map[string]int{}, Lights: map[string]int{}}
	reasons, brands, domains := map[string]int{}, map[string]int{}, map[string]int{}
	today := s.now().UTC()
	for i := days - 1; i >= 0; i-- {
		date := today.AddDate(0, 0, -i).Format(time.DateOnly)
		if i == days-1 {
			p.From = date
		}
		p.To = date
		day := statsDay{Date: date}
		if d := s.data.Days[date]; d != nil {
			for mode, n := range d.Submissions {
				p.Submissions[mode] += n
				day.Submissions += n
				if mode == modeUpload {
					p.Uploaded += n
				} else {
					p.Received += n
				}
			}
			p.Mails += d.Mails
			p.Analyses += d.Analyses
			p.QRCodes += d.QRCodes
			for light, n := range d.Lights {
				p.Lights[light] += n
			}
			day.Green, day.Orange, day.Red = d.Lights[riskGreen], d.Lights[riskOrange], d.Lights[riskRed]
			day.Others = d.Analyses - day.Green - day.Orange - day.Red
			addCounts(reasons, d.Reasons)
			addCounts(brands, d.Brands)
			addCounts(domains, d.Domains)
		}
		p.Daily = append(p.Daily, day)
	}
	p.Reasons, p.Brands, p.Domains = topCounts(reasons, 12), topCounts(brands, 15), topCounts(domains, 20)
	return p
}

func addCounts(to, from map[string]int) {
	for k, n := range from {
		to[k] += n
	}
}

// topCounts returns the largest counts, largest first.
func topCounts(m map[string]int, n int) []statsCount {
	keys := slices.Sorted(maps.Keys(m))
	slices.SortStableFunc(keys, func(a, b string) int { return m[b] - m[a] })
	var counts []statsCount
	for _, k := range keys[:min(n, len(keys))] {
		counts = append(counts, statsCount{Key: k, Count: m[k], Percent: m[k] * 100 / m[keys[0]]})
	}
	return counts
}
