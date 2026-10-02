package main

import (
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/smtpd"
)

//go:embed view/*.html
var views embed.FS

// purgeInterval is the delay between two removals of expired mailboxes.
const purgeInterval = 10 * time.Minute

func main() {
	configFile := flag.String("config", "./conf/configuration.json", "configuration file")
	flag.Parse()

	conf, err := getConfiguration(*configFile)
	if err != nil {
		log.Fatal("getConfiguration: ", err)
	}
	log.Printf("Configuration %+v\n", conf)

	store, err := newMailboxStore(conf.DataFolder, conf.Domains, conf.Retention.Duration, conf.MaxMailboxes)
	if err != nil {
		log.Fatal("opening data folder: ", err)
	}
	templates, err := template.ParseFS(views, "view/*.html")
	if err != nil {
		log.Fatal("parsing templates: ", err)
	}

	var tlsConfig *tls.Config
	if conf.tlsEnabled() {
		certs, err := newCertReloader(conf.Cert, conf.Key)
		if err != nil {
			log.Fatal("loading certificate: ", err)
		}
		tlsConfig = certs.tlsConfig()
	} else {
		log.Print("no certificate configured: HTTPS, STARTTLS and the submission ports are disabled")
	}

	s := &server{store: store, templates: templates, limiter: newRateLimiter(10, time.Hour)}
	go func() {
		for range time.Tick(purgeInterval) {
			store.PurgeExpired()
			s.limiter.prune()
		}
	}()

	errs := make(chan error)
	run := func(name, port string, serve func(addr string) error) {
		if port == "" {
			return
		}
		addr := net.JoinHostPort(conf.Server, port)
		log.Printf("%s listening on %s", name, addr)
		go func() { errs <- fmt.Errorf("%s: %w", name, serve(addr)) }()
	}

	smtpServer := &smtpd.Server{
		Hostname:       conf.Hostname,
		Backend:        store,
		TLSConfig:      tlsConfig,
		MaxMessageSize: conf.MaxMessageSize,
	}
	run("SMTP (MX)", conf.SMTPPorts.MX, func(addr string) error { return smtpServer.ListenAndServe(addr, smtpd.ModeMX) })
	if tlsConfig != nil {
		run("SMTP (submission)", conf.SMTPPorts.Submission, func(addr string) error { return smtpServer.ListenAndServe(addr, smtpd.ModeSubmission) })
		run("SMTPS", conf.SMTPPorts.SMTPS, func(addr string) error { return smtpServer.ListenAndServe(addr, smtpd.ModeImplicitTLS) })
	}

	app := s.routes(conf.StaticFolder)
	if tlsConfig != nil && conf.HTTPSPort != "" {
		run("HTTPS", conf.HTTPSPort, func(addr string) error {
			srv := newHTTPServer(addr, app)
			srv.TLSConfig = tlsConfig
			return srv.ListenAndServeTLS("", "")
		})
		run("HTTP (redirect)", conf.HTTPPort, func(addr string) error {
			return newHTTPServer(addr, redirectToHTTPS(conf.HTTPSPort, conf.ACMEWebroot)).ListenAndServe()
		})
	} else {
		run("HTTP", conf.HTTPPort, func(addr string) error { return newHTTPServer(addr, app).ListenAndServe() })
	}

	log.Fatal(<-errs)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
