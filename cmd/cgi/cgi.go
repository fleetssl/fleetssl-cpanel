package cgi

import (
	"mime"
	"net/http"
	"net/http/cgi"
	"strings"

	log "github.com/sirupsen/logrus"

	"os"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/cgi/cpanelcgi"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/cgi/whmcgi"
)

func Run() {
	// in fact the match for / works only because its a wildcard
	// the actual .URL is the full cPanel session one
	http.HandleFunc("/", serveCgi)
	if err := cgi.Serve(nil); err != nil {
		log.Fatal(err)
	}
}

// Root function for serving cgi requests
func serveCgi(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("SCRIPT_FILENAME") == "/usr/local/cpanel/whostmgr/docroot/cgi/letsencrypt-cpanel/letsencrypt.live.cgi" {
		whmcgi.ServeWhmCgi(w, r)
	} else {
		if isAPIRequest(r) {
			cpanelcgi.ServeCpanelCGIAPI(w, r)
		} else {
			cpanelcgi.ServeCpanelCgi(w, r)
		}
	}
}

func isAPIRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if parsedMediaType, _, _ := mime.ParseMediaType(r.Header.Get("content-type")); r.Header.Get("content-type") != "" && parsedMediaType != "application/json" {
		return false
	}
	for _, mt := range strings.Split(r.Header.Get("accept"), ",") {
		if parsedMediaType, _, _ := mime.ParseMediaType(mt); parsedMediaType == "application/json" {
			return true
		}
	}
	return false
}
