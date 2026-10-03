package main

import (
	"strings"

	"github.com/get-code-ch/mailtoolkit_webserver/mailauth"
)

// relayService is a service sending mails on behalf of its users: secure
// mail, e-signature, file sharing. Its mails show the user's address in the
// display name and reply to the user, which otherwise looks like spoofing.
type relayService struct {
	Name string
	// Senders are the sending domains (and their subdomains) of the service.
	Senders []string
	// Sites are the domains its links and forms lead to.
	Sites []string
}

var relayServices = []relayService{
	{"IncaMail (La Poste suisse)", []string{"im.post.ch", "incamail.com", "incamail.ch"}, []string{"incamail.com", "incamail.ch", "post.ch", "swisspost.ch"}},
	{"HIN Mail GLOBAL", []string{"hin.ch"}, []string{"hin.ch"}},
	{"PrivaSphere", []string{"privasphere.com"}, []string{"privasphere.com"}},
	{"SEPPmail", []string{"seppmail.com", "seppmail.cloud"}, []string{"seppmail.com", "seppmail.cloud"}},
	{"DocuSign", []string{"docusign.net", "docusign.com"}, []string{"docusign.net", "docusign.com"}},
	{"Adobe Acrobat Sign", []string{"adobesign.com", "echosign.com"}, []string{"adobesign.com", "echosign.com", "adobe.com"}},
	{"Google Workspace", []string{"google.com"}, []string{"google.com"}},
	{"Microsoft SharePoint", []string{"sharepointonline.com"}, []string{"sharepoint.com", "microsoft.com"}},
	{"Dropbox", []string{"dropbox.com", "dropboxmail.com"}, []string{"dropbox.com"}},
	{"WeTransfer", []string{"wetransfer.com"}, []string{"wetransfer.com"}},
}

// relayOf returns the service a sender domain belongs to, nil if none.
func relayOf(domain string) *relayService {
	domain = strings.ToLower(domain)
	for i, r := range relayServices {
		for _, d := range r.Senders {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return &relayServices[i]
			}
		}
	}
	return nil
}

// site reports whether a host belongs to the service.
func (r *relayService) site(host string) bool {
	if r == nil || host == "" {
		return false
	}
	org := mailauth.OrgDomain(strings.ToLower(host))
	for _, d := range r.Sites {
		if org == d || strings.HasSuffix(strings.ToLower(host), "."+d) {
			return true
		}
	}
	return false
}
