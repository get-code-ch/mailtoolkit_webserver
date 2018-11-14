package main

import (
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"regexp"
)

const userContext = "user-context"

var (
	//TODO: configure key as env variable
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, userContext)

	// Parse login form
	err := r.ParseForm()
	if err != nil {
		session.Values["authenticated"] = false
		session.Save(r, w)
		http.Error(w, "login() - Parse - Internal Server Error", http.StatusInternalServerError)
	}
	usr := r.Form["username"][0]
	pwd := r.Form["password"][0]
	search := regexp.MustCompile(`(?mi)^(` + usr + `):\{.*\}(.*)$`)

	// Check hashPwd authentication
	file, err := ioutil.ReadFile(conf.Users)
	if err != nil {
		session.Values["authenticated"] = false
		session.Save(r, w)
		http.Error(w, "login() - Users - Internal Server Error", http.StatusInternalServerError)
	}

	hashPwd := search.FindSubmatch(file)
	if hashPwd == nil || hashPwd[2] == nil {
		// Go to home page
		session.Values["authenticated"] = false
		session.Save(r, w)
		if conf.Ssl {
			http.Redirect(w, r, "https://"+r.Host+"/?msg=\"Invalid hashPwd or password!\"", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "http://"+r.Host+"/?msg=\"Invalid hashPwd or password!\"", http.StatusSeeOther)
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword(hashPwd[2], []byte(pwd)); err != nil {
		// Go to home page
		session.Values["authenticated"] = false
		session.Save(r, w)
		if conf.Ssl {
			http.Redirect(w, r, "https://"+r.Host+"/?msg=Invalid hashPwd or password!", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "http://"+r.Host+"/?msg=Invalid hashPwd or password!", http.StatusSeeOther)
		}
		return
	}

	// Set hashPwd as authenticated
	session.Values["authenticated"] = true
	session.Values["username"] = usr
	session.Save(r, w)

	// Go to home page
	if conf.Ssl {
		http.Redirect(w, r, "https://"+r.Host+"/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "http://"+r.Host+"/", http.StatusSeeOther)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, userContext)
	if auth, ok := session.Values["authenticated"].(bool); ok || auth {
		session.Values["authenticated"] = false
		session.Values["username"] = ""
		session.Save(r, w)
	}
	// Go to home page
	if conf.Ssl {
		http.Redirect(w, r, "https://"+r.Host+"/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "http://"+r.Host+"/", http.StatusSeeOther)
	}

}
