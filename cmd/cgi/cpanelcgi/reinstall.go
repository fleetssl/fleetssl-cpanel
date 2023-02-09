package cpanelcgi

import (
	"fmt"
	"net/http"
	"strings"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

func actionReinstall(data ActionData) ErrorList {
	domain := data.Req.FormValue("domain")

	_, validDomain := data.DomainList[domain]
	if !validDomain {
		return ErrorList{TS("Invalid domain specified"), domain}
	}

	cert, present := data.NVData.Certs[domain]
	if !present {
		return ErrorList{TS("Domain does not have a certificate"), domain}
	}

	alternateChainIssuers := []string{}
	for k := range cert.AlternateChains {
		alternateChainIssuers = append(alternateChainIssuers, k)
	}

	if data.Req.Method == "POST" {
		result, errs := ReinstallCertificate(data.Cpanel, data.NVData, cert, data.Req.FormValue("preferred_issuer"))
		if errs != nil {
			return errs
		}
		serveResult(data, result)
	} else {
		serveTemplate(data, "reinstall.html", map[string]interface{}{
			"Domain":          domain,
			"AltNames":        cert.AltNames,
			"PreferredIssuer": cert.PreferredIssuer,
			"AlternateChains": alternateChainIssuers,
		})
	}

	return nil
}

func ReinstallCertificate(cp cpanel.CpanelApi, nvdata *common.NVDataAccount, cert *common.NVDataDomainCerts,
	preferredIssuer string) (string, ErrorList) {

	preferredIssuerOrDefault := preferredIssuer
	if preferredIssuerOrDefault == "" {
		preferredIssuerOrDefault, _ = client.GetPreferredIssuer()
	}
	issuerCert := strings.ReplaceAll(cert.BestIssuer(preferredIssuerOrDefault)+"\n"+common.CABundle, "\n\n", "\n")

	// This is to work around some bug with cPanel 99 not updating the cabundle properly on reinstall.
	_, _ = cp.DeleteSSL(cert.Domain)

	// Install the certificate to cPanel/Apache
	install, err := cp.InstallSSLKey(cert.Domain, cert.DomainCert, cert.DomainKey, issuerCert)
	if err != nil {
		return "", ErrorList{TS("Error re-installing ssl certificate on domain"), cert.Domain, err}
	}

	// preferredIssuer is always specified; the user is making a decision and we should remember it for renewal.
	cert.PreferredIssuer = preferredIssuer

	// Save the new certificate ID and key ID to nvdata
	cert.CertId = install.Data.CertId
	cert.KeyId = install.Data.KeyId
	if _, err = cp.SetNVData(common.NVDatastoreName, nvdata); err != nil {
		return "", ErrorList{TS("Unable to update installed ssl certificate in nvdata"), cert.Domain, err}
	}

	// Re-install to the re-use targets as well
	for _, target := range nvdata.GetReuseTargetsForSource(cert.Domain) {
		if _, err := cp.InstallSSLKey(target, cert.DomainCert, cert.DomainKey, issuerCert); err != nil {
			return "", ErrorList{TF("Unable to install certificate (re-used) to domain: %s", target), err}
		}
	}

	return install.Message(), nil
}

type reinstallCertificateRequest struct {
	VirtualHost     string `json:"virtual_host"`
	PreferredIssuer string `json:"preferred_issuer"`
}

func (h apiHandler) reinstallCertificate(w http.ResponseWriter, r *http.Request) {
	var req reinstallCertificateRequest
	if err := processAPIRequestBody(w, r, &req); err != nil {
		return
	}

	if req.VirtualHost == "" {
		serveAPIError(w, http.StatusBadRequest, "The target `virtual_host` must be provided")
		return
	}

	nvdata, err := common.GetAndParseNVData(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to get account nvdata", err.Error())
		return
	}
	certToReinstall, ok := nvdata.Certs[req.VirtualHost]
	if !ok {
		serveAPIError(w, http.StatusNotFound,
			fmt.Sprintf("Could not locate virtual host '%s' within existing certificates", req.VirtualHost))
		return
	}

	msg, errs := ReinstallCertificate(h.cpanelAPI, nvdata, certToReinstall, req.PreferredIssuer)
	if errs != nil {
		serveAPIError(w, http.StatusInternalServerError, errs.GatherErrors()...)
		return
	}

	serveAPISuccess(w, http.StatusOK, msg)
}
