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
	"strconv"
	"strings"
	"sync"
)

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

const file = "./conf/configuration.json"

var mailLst []mailtoolkit.Mail

var conf Configuration
var removeCid *regexp.Regexp

func init() {
	var err error
	conf, err = getConfiguration(file)
	if err != nil {
		log.Fatal("getConfiguration: ", err)
	}
	removeCid = regexp.MustCompile(`(?mi)(src=["]?)(cid:)(["]?)`)

	emailLst := []os.FileInfo{}

	// Get email files in folder
	files, err := ioutil.ReadDir(conf.MailFolder)
	if err != nil {
		log.Fatal(err)
	}

	for _, fn := range files {
		if filepath.Ext(fn.Name()) == ".eml" {
			emailLst = append(emailLst, fn)
		}
	}

	sg := sync.WaitGroup{}
	sg.Add(len(emailLst))

	results := make(chan mailtoolkit.Mail, 100)

	// Parse mailcontent to an array
	for _, fn := range emailLst {
		go func(name string) {
			r := mailtoolkit.Mail{}
			buffer, err := ioutil.ReadFile(conf.MailFolder + name)
			if err != nil {
				log.Printf("Error open mail file: %v", err)
				sg.Done()
				return
			}
			r = mailtoolkit.Parse(buffer)
			results <- r
			sg.Done()
		}(fn.Name())
	}

	go func() {
		sg.Wait()
		close(results)
	}()

	mailLst = []mailtoolkit.Mail{}
	for m := range results {
		mailLst = append(mailLst, m)
	}

}

func root(w http.ResponseWriter, r *http.Request) {
	p := []mailTpl{}
	for i, m := range mailLst {
		r := mailTpl{}
		r.From = m.Header.From
		r.To = m.Header.To
		r.Subject = m.Header.Subject
		r.Content = []Href{}
		r.Attachment = []Href{}
		for c := range m.Contents {
			r.Content = append(r.Content, Href{"/mail/" + strconv.Itoa(i) + "/" + c, m.Contents[c].ContentInfo.Type.Type + "/" + m.Contents[c].ContentInfo.Type.Subtype})
		}
		for a := range m.Attachments {
			r.Attachment = append(r.Attachment, Href{"/mail/" + strconv.Itoa(i) + "/attachment/" + a, a})
		}
		p = append(p, r)
	}

	h, err := ioutil.ReadFile("view/home.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	t, err := template.New("home").Parse(string(h))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Title string
		Mail  []mailTpl
	}{Title: "mailtoolkit demo webserver", Mail: p}

	t.Execute(w, data)
}

func mailContent(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var err error
	var contentType string

	vars := mux.Vars(r)

	id, _ := strconv.Atoi(vars["id"])
	contentKey, _ := vars["content"]
	if id >= len(mailLst) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	content, ok := mailLst[id].Contents[contentKey]
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
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
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
	var data []byte
	var err error
	var attachmentType string

	vars := mux.Vars(r)

	id, _ := strconv.Atoi(vars["id"])
	attachmentKey, _ := vars["attachment"]
	if id >= len(mailLst) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	attachment, ok := mailLst[id].Attachments[attachmentKey]
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
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
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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

	// Display select mail content
	router.HandleFunc("/mail/{id}/{content}", mailContent)
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
