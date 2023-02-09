package cpanelcgi

import (
	"net/http"
	"time"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

func actionHome(data ActionData) ErrorList {

	// set the status based on the cert being actually installed
	list, err := data.Cpanel.InstalledHosts()
	if err != nil {
		return ErrorList{TS("Error fetching installed ssl certs"), err}
	}

	status := getDomainStatus(data, list)

	groupedDomains, _, err := common.GroupAllDomains(data.DomainList)
	if err != nil {
		return ErrorList{TS("Error grouping domain names"), err}
	}

	serveTemplate(data, "home.html", map[string]interface{}{
		"Certs":            data.NVData.Certs,
		"Reuses":           data.NVData.Reuses,
		"Domains":          data.DomainList,
		"GroupedDomains":   groupedDomains,
		"Status":           status,
		"LastRenewalCheck": data.NVData.LastRenewalCheck,
		"Version":          common.AppVersion,
	})

	return nil
}

type installedCert struct {
	CommonName string
	CertId     string
	NotAfter   string
	SelfSigned string
	Names      []string
}

func getDomainStatus(data ActionData, installedHosts cpanel.InstalledHostsApiResponse) map[string]string {
	// map of certid to status
	status := map[string]string{}

	for domain, accountCert := range data.NVData.Certs {
		if accountCert.DomainKey == "" {
			// if no domain key, must be broken in some way
			status[accountCert.CertId] = TS("Broken key! Contact support")
			continue
		}
		if accountCert.DomainCert == "" {
			status[accountCert.CertId] = TS("Broken cert! Contact support")
			continue
		}

		// domain removed from system
		if _, present := data.DomainList[domain]; !present {
			status[accountCert.CertId] = TS("Domain Removed")
			continue
		}

		// check if this certificate is installed
		found := false
		var installedCert cpanel.InstalledCertificate
		for _, installed := range installedHosts.Data {
			if accountCert.CertId == installed.Certificate.Id {
				found = true
				installedCert = installed
				break
			}
		}
		if !found {
			status[accountCert.CertId] = TS("Not installed")
			continue
		}

		// expired
		if int64(installedCert.Certificate.NotAfter) < time.Now().Unix() {
			status[accountCert.CertId] = TS("Expired")
		}

		// must be installed
		status[accountCert.CertId] = TS("Installed")
	}

	return status
}

type listCertificatesResponse struct {
	VirtualHosts map[string]listCertificatesEntry `json:"virtual_hosts"`
}

type listCertificatesEntry struct {
	VirtualHost     string   `json:"virtual_host"`
	DNSIdentifiers  []string `json:"dns_identifiers"`
	ChallengeMethod string   `json:"challenge_method"`
	CPanelCertID    string   `json:"cpanel_cert_id"`
	CPanelKeyID     string   `json:"cpanel_key_id"`
	CertificatePEM  string   `json:"cert_pem"`
	IssuerPEM       string   `json:"issuer_pem"`
	PrivateKeyPEM   string   `json:"privkey_pem"`
	OrderURL        string   `json:"order_url"`
}

func (h apiHandler) listCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		serveAPIError(w, http.StatusBadRequest, "You must use GET for this endpoint")
		return
	}

	nvdata, err := common.GetAndParseNVData(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to get account nvdata", err.Error())
		return
	}

	resp := listCertificatesResponse{
		VirtualHosts: map[string]listCertificatesEntry{},
	}

	for vhost, cert := range nvdata.Certs {
		resp.VirtualHosts[vhost] = listCertificatesEntry{
			VirtualHost:     vhost,
			DNSIdentifiers:  common.AppendIfNotExist(cert.AltNames, cert.Domain),
			ChallengeMethod: cert.ChallengeMethod,
			CertificatePEM:  cert.DomainCert,
			PrivateKeyPEM:   cert.DomainKey,
			IssuerPEM:       cert.IssuerCert,
			CPanelCertID:    cert.CertId,
			CPanelKeyID:     cert.KeyId,
			OrderURL:        cert.OrderUrl,
		}
	}

	serveAPISuccess(w, http.StatusOK, resp)
}
