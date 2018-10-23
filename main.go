package main

import (
	"github.com/get-code-ch/mailtoolkit"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

const file = "./conf/configuration.json"

func root(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}

func main() {
	var mail mailtoolkit.Mail
	_ = mail

	conf, err := getConfiguration(file)
	if err != nil {
		log.Fatal("getConfiguration: ", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/", root)

	http.Handle("/", router)
	if conf.Ssl {
		err = http.ListenAndServeTLS(conf.Server+":"+conf.Port, conf.Cert, conf.Key, nil)
	} else {
		err = http.ListenAndServe(conf.Server+":"+conf.Port, nil)
	}
	if err != nil {
		log.Fatal("ListenAndServer:", err)
	}
}
