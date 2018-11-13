package main

import (
	"encoding/base64"
	"github.com/get-code-ch/mailtoolkit"
	"github.com/gorilla/mux"
	"html/template"
	"io/ioutil"
	"log"
	"mime/quotedprintable"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const file = "./conf/configuration.json"

// Template to display mail list in array
type mailTpl struct {
	From       string
	To         string
	Subject    string
	Date       string
	Content    []Href
	Attachment []Href
}

type Href struct {
	Link string
	Text string
}

var mailLst map[string]mailtoolkit.Mail

var conf Configuration
var removeCid *regexp.Regexp
var templateLayout []string

func init() {
	var err error

	// Get configuration
	conf, err = getConfiguration(file)
	if err != nil {
		log.Fatal("getConfiguration(): ", err)
	}

	// Load regex expression
	removeCid = regexp.MustCompile(`(?mi)(src=["]?)(cid:)(["]?)`)

	mailLst = make(map[string]mailtoolkit.Mail)

	// Define ground template
	templateLayout = []string{"view/layout.html", "view/header.html", "view/footer.html"}

	log.Printf("Configuration loaded...\n")
}

func root(w http.ResponseWriter, r *http.Request) {
	var emailLst []os.FileInfo
	var msg []string

	// check if user is authenticated
	// If authenticated --> loading mail list
	// If not --> display login panel

	session, _ := store.Get(r, userContext)

	msg, ok := r.URL.Query()["msg"]
	if !ok {
		msg = make([]string, 1)
		msg[0] = ""
	}
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		view := append(templateLayout, "view/logon.html")
		t, err := template.ParseFiles(view...)
		if err != nil {
			http.Error(w, "root() - logon template - Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := struct {
			Title   string
			Message string
		}{Title: "mailtoolkit demo", Message: msg[0]}
		t.ExecuteTemplate(w, "layout", data)
		return
	}

	// Get email files in folder
	//TODO: get folder content depending of user context
	files, err := ioutil.ReadDir(conf.MailFolder)
	if err != nil {
		http.Error(w, "root() - reading mail folder  - Internal Server Error", http.StatusInternalServerError)
		log.Printf("root() - Error reading mail folder %v", err)
		return
	}

	for _, fn := range files {
		if filepath.Ext(fn.Name()) == conf.Ext || conf.Ext == ".*" {
			emailLst = append(emailLst, fn)
		}
	}

	// go rountine to parse mail to an array
	sg := sync.WaitGroup{}
	sg.Add(len(emailLst))

	results := make(chan map[string]mailtoolkit.Mail, 100)

	for _, fn := range emailLst {
		go func(name string) {
			if _, ok := mailLst[name]; !ok {
				r := map[string]mailtoolkit.Mail{}
				buffer, err := ioutil.ReadFile(conf.MailFolder + name)
				if err != nil {
					sg.Done()
					log.Printf("Error open mail file: %v", err)
					http.Error(w, "root() - logon template - Internal Server Error", http.StatusInternalServerError)
					return
				}
				r[name] = mailtoolkit.Parse(buffer)
				results <- r
			}
			sg.Done()
		}(fn.Name())
	}

	// Wait for until all files are processed
	go func() {
		sg.Wait()
		close(results)
	}()

	for maps := range results {
		for key, value := range maps {
			mailLst[key] = value
		}
	}

	var p []mailTpl
	for key, value := range mailLst {
		r := mailTpl{}
		r.From = value.Header.From
		r.To = value.Header.To
		r.Subject = value.Header.Subject
		r.Content = []Href{}
		r.Attachment = []Href{}
		for c := range value.Contents {
			r.Content = append(r.Content, Href{"/display/" + key + "/" + c, value.Contents[c].ContentInfo.Type.Type + "/" + value.Contents[c].ContentInfo.Type.Subtype})
		}
		for a := range value.Attachments {
			r.Attachment = append(r.Attachment, Href{"/mail/" + key + "/attachment/" + a, a})
		}
		p = append(p, r)
	}

	view := append(templateLayout, "view/list.html")
	t, err := template.ParseFiles(view...)
	if err != nil {
		http.Error(w, "root() - List mail - Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Title string
		Mail  []mailTpl
	}{Title: "mailtoolkit demo", Mail: p}

	t.ExecuteTemplate(w, "layout", data)
}

func displayContent(w http.ResponseWriter, r *http.Request) {

	// Check if user is authenticated
	session, _ := store.Get(r, userContext)
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		if conf.Ssl {
			http.Redirect(w, r, "https://"+r.Host+"/", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "http://"+r.Host+"/", http.StatusSeeOther)
		}
		return
	}

	vars := mux.Vars(r)

	id, _ := vars["id"]
	contentKey, _ := vars["content"]

	view := append(templateLayout, "view/mail.html")
	t, err := template.ParseFiles(view...)
	if err != nil {
		http.Error(w, "displayContent() - Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Title       string
		Header      mailtoolkit.Header
		ContentInfo mailtoolkit.ContentInfo
		Content     string
	}{Title: mailLst[id].Header.Subject, Header: mailLst[id].Header, ContentInfo: mailLst[id].Contents[contentKey].ContentInfo, Content: "/mail/" + id + "/" + contentKey}

	t.ExecuteTemplate(w, "layout", data)
}

func mailContent(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, _ := store.Get(r, userContext)
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		w.Write([]byte(""))
		return
	}

	var data []byte
	var err error
	var contentType string

	vars := mux.Vars(r)

	id, _ := vars["id"]
	contentKey, _ := vars["content"]
	content, ok := mailLst[id].Contents[contentKey]
	if !ok {
		http.Error(w, "mailContent() - Content not Found", http.StatusNotFound)
		return
	}

	contentType = content.ContentInfo.Type.Type + "/" + content.ContentInfo.Type.Subtype
	for key, value := range content.ContentInfo.Type.Parameters {
		contentType += " ;" + key + "=" + value
	}

	switch content.ContentInfo.TransferEncoding {
	case "base64":
		data = make([]byte, base64.StdEncoding.DecodedLen(len(content.Data)))
		base64.StdEncoding.Decode(data, content.Data)
		data = removeCid.ReplaceAll(data, []byte("$1$3"))
	case "quoted-printable":
		data, err = ioutil.ReadAll(quotedprintable.NewReader(strings.NewReader(string(content.Data))))
		if err != nil {
			http.Error(w, "mailContent() - quoted-printable - Internal Server Error", http.StatusInternalServerError)
			return
		}
		data = removeCid.ReplaceAll(data, []byte("$1$3"))
	default:
		data = removeCid.ReplaceAll(content.Data, []byte("$1$3"))
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

func mailAttachment(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, _ := store.Get(r, userContext)
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		w.Write([]byte(""))
		return
	}

	var data []byte
	var err error
	var attachmentType string

	vars := mux.Vars(r)

	id, _ := vars["id"]
	attachmentKey, _ := vars["attachment"]
	attachment, ok := mailLst[id].Attachments[attachmentKey]
	if !ok {
		http.Error(w, "mailAttachment() - Attachment not Found", http.StatusNotFound)
		return
	}

	attachmentType = attachment.ContentInfo.Type.Type + "/" + attachment.ContentInfo.Type.Subtype
	for key, value := range attachment.ContentInfo.Type.Parameters {
		attachmentType += " ;" + key + "=" + value
	}

	switch attachment.ContentInfo.TransferEncoding {
	case "base64":
		data = make([]byte, base64.StdEncoding.DecodedLen(len(attachment.Data)))
		base64.StdEncoding.Decode(data, attachment.Data)
	case "quoted-printable":
		data, err = ioutil.ReadAll(quotedprintable.NewReader(strings.NewReader(string(attachment.Data))))
		if err != nil {
			http.Error(w, "mailAttachment() - quoted-printable - Internal Server Error", http.StatusInternalServerError)
		}
	default:
		data = attachment.Data
	}
	w.Header().Set("Content-Type", attachmentType)
	w.Write(data)
}

func main() {
	var err error

	router := mux.NewRouter()

	// Display list of emails
	router.HandleFunc("/", root)

	// Process user auth
	router.HandleFunc("/login", login).Methods("POST")

	// Display select mail content
	router.HandleFunc("/mail/{id}/{content}", mailContent)
	router.HandleFunc("/display/{id}/{content}", displayContent)
	router.HandleFunc("/mail/{id}/attachment/{attachment}", mailAttachment)
	// Serving static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(conf.StaticFolder))))

	if conf.Ssl {
		err = http.ListenAndServeTLS(conf.Server+":"+conf.Port, conf.Cert, conf.Key, router)
	} else {
		err = http.ListenAndServe(conf.Server+":"+conf.Port, router)
	}
	if err != nil {
		log.Fatal("ListenAndServer:", err)
	}
}
