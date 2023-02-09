package daemon

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"context"
)

var (
	httpClient *http.Client
)

func serveCgiConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch r.FormValue("config") {
	case "customdomains":
		fmt.Fprint(w, fmt.Sprint(config.EnableCustomDomains))
		return
	case "autosslenabled":
		fmt.Fprint(w, fmt.Sprint(config.AutoSSL))
		return
	case "crypto_params":
		buf, _ := json.Marshal(map[string]interface{}{
			"Alg":        strings.ToLower(config.CryptoKeyType),
			"RsaKeySize": config.CryptoRsaKeySize,
			"EcdsaCurve": strings.ToLower(config.CryptoEcdsaCurve),
		})
		fmt.Fprint(w, string(buf))
		return
	case "challenge_methods":
		json.NewEncoder(w).Encode(config.ChallengeMethods)
		return
	case "dns_challenge_delay_secs":
		fmt.Fprint(w, strconv.Itoa(*config.DNSChallengeDelay))
	case "ui_autochecked_prefixes":
		if config.AutocheckedPrefixes != nil {
			fmt.Fprint(w, strings.Join(*config.AutocheckedPrefixes, ","))
		}
	case "preferred_issuer_cn":
		fmt.Fprint(w, config.PreferredIssuerCN)
	default:
		http.Error(w, "Invalid config: "+r.FormValue("config"), http.StatusBadRequest)
		return
	}
}

func serve6to4Proxy(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dom := q.Get("domain")
	path := q.Get("challenge-path")

	if dom == "" || path == "" {
		http.Error(w, "Invalid parameters", 400)
		return
	}

	// Path must validate as base64url
	b64urlRegex := regexp.MustCompile(`^[A-Za-z0-9_=\-]+$`)
	if !b64urlRegex.MatchString(path) {
		http.Error(w, "Invalid parameters", 400)
		return
	}

	// Normalize th edomain
	dom = strings.ToLower(strings.TrimSpace(dom))

	// Remote client must be loopback
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remote != "127.0.0.1" && remote != "::1" {
		http.Error(w, "Invalid request", 400)
		return
	}

	// We use this because it guarantees to resolve IPv4, in cPanel 68
	ip, err := whmCl.ResolveDomainName(dom)
	if err != nil || ip.Data.IP == "" {
		http.Error(w, "Invalid domain", http.StatusInternalServerError)
		return
	}

	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives:   true,
				MaxIdleConns:        1,
				MaxIdleConnsPerHost: 1,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DialContext: (&net.Dialer{
					DualStack: false,
				}).DialContext,
			},
		}
	}

	req, err := http.NewRequest("GET", "http://"+ip.Data.IP+"/.well-known/acme-challenge/"+path, nil)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	req.Host = dom
	req.Header.Set("Host", dom)
	req.Header.Set("User-Agent", r.UserAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.CopyN(w, resp.Body, 8192)
}

func listen(exitCh chan<- error) {
	mux := http.DefaultServeMux
	mux.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
	})
	mux.HandleFunc("/cgi-config", serveCgiConfig)
	mux.HandleFunc("/6to4proxy", serve6to4Proxy)

	if err := http.ListenAndServe("127.0.0.1:5959", nil); err != nil {
		exitCh <- fmt.Errorf("Error starting server: %v", err)
	}

}
