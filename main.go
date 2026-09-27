package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"
)

const file = "./conf/configuration.json"

//go:embed view/*.html
var views embed.FS

func main() {
	conf, err := getConfiguration(file)
	if err != nil {
		log.Fatal("getConfiguration: ", err)
	}
	log.Printf("Configuration %+v\n", conf)

	store, err := newMailStore(conf.MailFolder, conf.Ext)
	if err != nil {
		log.Fatal("opening mail folder: ", err)
	}
	templates, err := template.ParseFS(views, "view/*.html")
	if err != nil {
		log.Fatal("parsing templates: ", err)
	}

	s := &server{store: store, templates: templates}
	httpServer := &http.Server{
		Addr:              conf.Server + ":" + conf.Port,
		Handler:           s.routes(conf.StaticFolder),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if conf.Ssl {
		err = httpServer.ListenAndServeTLS(conf.Cert, conf.Key)
	} else {
		err = httpServer.ListenAndServe()
	}
	log.Fatal("ListenAndServe: ", err)
}
