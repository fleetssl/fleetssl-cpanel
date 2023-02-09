package cpanelcgi

import (
	"fmt"
	"net/http"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

func actionRemove(data ActionData) ErrorList {
	domain := data.Req.FormValue("domain")

	storedCert, present := data.NVData.Certs[domain]
	if !present {
		return ErrorList{TS("Domain does not have a stored certificate"), domain}
	}

	if data.Req.Method == "POST" {
		result := removeCertificate(data.NVData, data.Cpanel, storedCert, domain)
		if result != nil || len(result) > 0 {
			el := ErrorList{TS("Some errors occured removing certificate for domain"), domain}
			return append(el, result...)
		}
		serveResult(data, TS("Certificate was removed for domain"), domain)
	} else {
		serveTemplate(data, "remove.html", storedCert)
	}
	return nil
}

func actionRemoveReuse(data ActionData) ErrorList {
	domain := data.Req.FormValue("domain")

	if err := common.UnmapCertificateReuse(data.Cpanel, data.NVData, domain); err != nil {
		return ErrorList{TS(err.Error())}
	}

	serveResult(data, TS("Certificate re-use mapping removed and certificate uninstalled."))

	return nil
}

// Delete's SSL from the domain, deletes the certificate and deletes the key. If successful,
// deletes the entry from the user's nvdata.
func removeCertificate(nvdata *common.NVDataAccount, cp cpanel.CpanelApi, storedCert *common.NVDataDomainCerts, domain string) ErrorList {

	// remove from cpanel
	cpanelResult := removeInstalledCertificate(cp, storedCert, domain)

	// remove from nvdata
	nvdataResult := removeStoredCertificate(nvdata, cp, domain)

	// if both succeeded, return no errors
	if cpanelResult == nil && nvdataResult == nil {
		return nil
	}

	var results ErrorList

	if cpanelResult != nil {
		results = append(results, TS("An error occured removing the installed certificate from cPanel"))
		results = append(results, cpanelResult...)
	}

	if nvdataResult != nil {
		results = append(results, TS("An error occured removing the stored certificate data"))
		results = append(results, nvdataResult...)
	}

	return results
}

func removeInstalledCertificate(cp cpanel.CpanelApi, storedCert *common.NVDataDomainCerts, domain string) ErrorList {
	hosts, err := cp.InstalledHosts()
	if err != nil {
		return ErrorList{TS("Error fetching domains with installed SSL certificates, installed certificate not removed"), err}
	}

	var results ErrorList

	if hosts.HasDomain(domain) {
		if _, err := cp.DeleteSSL(domain); err != nil {
			results = append(results, TF("Could not remove SSL for domain: %s", domain), err)
		}
	}
	if storedCert.CertId != "" {
		if _, err := cp.DeleteCert(storedCert.CertId); err != nil {
			results = append(results, TF("Could not remove certificate id: %s", storedCert.CertId), err)
		}
	}
	if storedCert.KeyId != "" {
		if _, err := cp.DeleteKey(storedCert.KeyId); err != nil {
			results = append(results, TF("Could not remove key id: %s", storedCert.KeyId), err)
		}
	}

	return results
}

func removeStoredCertificate(nvdata *common.NVDataAccount, cp cpanel.CpanelApi, domain string) ErrorList {
	// delete from nvdata
	delete(nvdata.Certs, domain)
	if _, err := cp.SetNVData(common.NVDatastoreName, nvdata); err != nil {
		return ErrorList{TS("Unable to remove stored certificate data"), err}
	}
	return nil
}

type removeCertificateRequest struct {
	// VirtualHost is the target virtualhost to remove the certificate configuration from
	VirtualHost string `json:"virtual_host"`
}

// Equivalent of action=remove
func (h apiHandler) removeCertificate(w http.ResponseWriter, r *http.Request) {
	var req removeCertificateRequest
	if err := processAPIRequestBody(w, r, &req); err != nil {
		return
	}

	if req.VirtualHost == "" {
		serveAPIError(w, http.StatusBadRequest, "The target `virtual_host` must be provided")
		return
	}

	// Gather up data from the cPanel account required to remove the certificate
	// NVData
	nvdata, err := common.GetAndParseNVData(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to get account nvdata", err.Error())
		return
	}

	certToRemove, ok := nvdata.Certs[req.VirtualHost]
	if !ok {
		serveAPIError(w, http.StatusNotFound,
			fmt.Sprintf("Could not locate virtual host '%s' within configured certificates", req.VirtualHost))
		return
	}

	errs := removeCertificate(nvdata, h.cpanelAPI, certToRemove, req.VirtualHost)
	if errs != nil && len(errs) > 0 {
		serveAPIError(w, http.StatusInternalServerError, errs.GatherErrors()...)
		return
	}

	serveAPISuccess(w, http.StatusOK, nil)
}

type removeCertificateReuseRequest struct {
	DestinationVirtualHost string `json:"dest_virtual_host"`
}

func (h apiHandler) removeCertificateReuse(w http.ResponseWriter, r *http.Request) {
	var req removeCertificateReuseRequest
	if err := processAPIRequestBody(w, r, &req); err != nil {
		return
	}

	if req.DestinationVirtualHost == "" {
		serveAPIError(w, http.StatusBadRequest, "`dest_virtual_host` must be provided")
		return
	}

	nvdata, err := common.GetAndParseNVData(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to get account nvdata", err.Error())
		return
	}

	if err := common.UnmapCertificateReuse(h.cpanelAPI, nvdata, req.DestinationVirtualHost); err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to apply certificate re-use", err.Error())
		return
	}

	serveAPISuccess(w, http.StatusOK, nil)
}
