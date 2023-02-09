package cpanelcgi

import (
	"fmt"
	"net/http"
	"os/user"
	"strings"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	log "github.com/sirupsen/logrus"
)

func actionIssue(data ActionData) ErrorList {

	quota, err := data.Cpanel.GetQuotaInfo()
	if err != nil {
		log.WithError(err).Println("Failed to fetch quota info")
	} else if !quota.IsUnderQuota() {
		return ErrorList{TS("Over disk quota, please free up disk space before continuing")}
	}

	u, err := user.Current()
	if err != nil {
		return ErrorList{TS("Couldn't determine current user")}
	}
	proxyLabels, err := common.GetProxyDomainLabels(u.Username, data.Cpanel)
	if err != nil {
		log.WithError(err).WithField("user", u.Username).Error("Couldn't fetch proxy subdomains")
		proxyLabels = []string{}
	}

	challengeMethods, _ := client.GetChallengeMethods()
	cryptoParams := client.GetCryptoParams()
	prefIssuer, _ := client.GetPreferredIssuer()

	if data.Req.Method == "POST" {
		// If we don't have an account key, generate and store one
		if len(data.NVData.AccountKey) == 0 {
			if err := common.CreateAccountKey(data.NVData, data.Cpanel, cryptoParams); err != nil {
				return ErrorList{TS("Creating Let's Encrypt account private key"), err}
			}
		}

		data.Req.ParseForm()

		mode := data.Req.FormValue("mode")
		if mode == "reuse" /* We're re-using an exising nvdata cert for another virtualhost */ {
			domainToInstallTo := data.Req.FormValue("domain")
			certToReuse := data.Req.FormValue("cert_to_reuse")

			if err := common.MapCertificateReuse(data.Cpanel, data.NVData, certToReuse, domainToInstallTo); err != nil {
				return ErrorList{TS(err.Error())}
			}

			serveResult(data, TF("Successfully mapped %s to re-use the certificate from %s.", domainToInstallTo, certToReuse))
		} else /* Regular issuance */ {
			isDryRun := data.Req.FormValue("dry_run") == "1"
			domain := data.Req.FormValue("domain")

			aliasDomains, present := data.Req.Form["aliasdomain"]
			if !present {
				return ErrorList{TS("No domains selected")}
			}

			method := data.Req.Form.Get("challenge_method")
			methodOk := false
			for _, v := range challengeMethods {
				if len(v) > 0 && v == method {
					methodOk = true
					break
				}
			}
			if !methodOk {
				return ErrorList{TS("That challenge method is not permitted")}
			}

			requestedKeyType := data.Req.Form.Get("key_type")
			keyParams, err := client.KeyTypeStringToParams(requestedKeyType)
			if err != nil {
				return ErrorList{TF("Requested key type %s is not a valid choice: %s", requestedKeyType, err.Error())}
			}

			proxyDomainsIssuing := data.Req.Form["proxydomain"]

			groupedDomains, _, err := common.GroupDomains(aliasDomains, data.DomainList, domain)
			if err != nil {
				return ErrorList{err}
			}

			results := []string{}

			for root, list := range groupedDomains {

				// check its valid
				primaryEntry := common.DomainEntry{}
				for _, entry := range list {
					if entry.Domain == root {
						primaryEntry = entry
						break
					}
				}
				if primaryEntry.Domain == "" {
					return ErrorList{TF("Unable to find root domain for: %s", root)}
				}

				// Prepend proxy labels for each domain that
				// was selected to have proxy subdomains
				for _, pxd := range proxyDomainsIssuing {
					if pxd != primaryEntry.Domain {
						continue
					}

					for _, proxyLabel := range proxyLabels {
						proxyLabel = strings.TrimSpace(proxyLabel)
						if len(proxyLabel) == 0 {
							continue
						}
						list.AddDomain(proxyLabel+"."+pxd, "Proxy", primaryEntry.DocumentRoot, primaryEntry.User, primaryEntry.DomainRoot)
					}
				}

				// issue certificate
				issueResult, err := issueCertificate(
					data.NVData, list.GatherNames(), primaryEntry,
					data.Cpanel, method, prefIssuer, isDryRun,
					keyParams,
				)
				if err != nil {
					return ErrorList{TS("Error issuing certificate"), issueResult, err}
				}

				results = append(results, issueResult)
			}

			serveResult(data, results...)
		}
	} else { // method == GET
		domain := data.Req.FormValue("domain")
		if domain == "" {
			return ErrorList{TS("No domains selected")}
		}

		mode := data.Req.FormValue("mode")
		if mode == "reuse" {
			serveTemplate(data, "issue-reuse.html", map[string]interface{}{
				"DomainRoot": domain,
				"Certs":      data.NVData.Certs,
			})
		} else {
			allDomains, _, err := common.GroupAllDomains(data.DomainList)
			if err != nil {
				return ErrorList{TS("Failed to group domain names")}
			}

			existing := map[string]bool{}
			checkedPrefixes, _ := client.GetAutocheckedPrefixes()
			for _, prefix := range checkedPrefixes {
				existing[prefix+domain] = true
			}
			// put any existing domains to be checked
			if existingCert, ok := data.NVData.Certs[domain]; ok {
				existing[existingCert.Domain] = true
				for _, v := range existingCert.AltNames {
					existing[v] = true
				}
			}

			groupedDomainsForSelected, present := allDomains[domain]
			if !present {
				return ErrorList{TS("Invalid domain selected")}
			}

			// check there's no groups with only custom domains
			onlyCustom := true
			for _, d := range groupedDomainsForSelected {
				if d.DomainType != "Custom" {
					onlyCustom = false
					break
				}
			}
			if onlyCustom {
				return ErrorList{TS("Error issuing certificate for"), domain, TS("Must have at least one non-custom domain selected")}
			}

			// Each domain may have proxy labels
			proxyDomainsMap := map[string][]string{}
			for d := range allDomains {
				proxyDomainsMap[d] = proxyLabels
			}

			serveTemplate(data, "issue.html", map[string]interface{}{
				"DomainRoot": domain,
				"Domains": map[string]common.DomainList{
					domain: groupedDomainsForSelected,
				},
				"Existing":         existing,
				"ProxyDomains":     proxyDomainsMap,
				"ChallengeMethods": challengeMethods,
				"DefaultKeyType":   cryptoParams.String(),
			})
		}
	}

	return nil
}

func issueCertificate(account *common.NVDataAccount, altDomains []string, mainDomain common.DomainEntry,
	cl cpanel.CpanelApi, method string, preferredIssuerCN string, dryRun bool, keyParams client.CryptoParams) (string, error) {

	if !dryRun {
		// Remove upto 1 expired/old cert before we do anything
		if err := common.CleanupOldCerts(mainDomain.User, cl, account, 1); err != nil {
			log.WithField("user", mainDomain.User).WithError(err).Warn("Failed to remove old certs")
		}
	}

	// construct all domain list with primary being the [0]
	domains := []string{mainDomain.Domain}
	for _, alt := range altDomains {
		// make sure we don't double up on any domains
		domains = common.AppendIfNotExist(domains, alt)
	}

	// get the cert
	cert, err := common.RequestCert(common.CertificateRequest{
		AccountKeyPEM:   account.AccountKey,
		Domains:         domains,
		DocRoots:        []string{mainDomain.DocumentRoot},
		Method:          method,
		CpanelAPI:       cl,
		PKF:             common.DefaultPrivateKeyFunc(keyParams),
		PreferredIssuer: preferredIssuerCN,
		DryRun:          dryRun,
	})
	if err != nil {
		return TS("Failed to issue certificate"), err
	}

	if dryRun {
		return TF("The dry run succeeded, a test certificate was issued and discarded: %s", cert.OrderUrl), nil
	}

	if account.Certs == nil {
		account.Certs = map[string]*common.NVDataDomainCerts{}
	}

	// Save the result immediately, even if we dont have the cert
	account.Certs[mainDomain.Domain] = cert
	if _, err := cl.SetNVData(common.NVDatastoreName, account); err != nil {
		return TS("Failed to store initial data about certificate"), err
	}

	// otherwise, we immediately have the cert

	// clear any existing certificate reuse
	account.ClearReuse(mainDomain.Domain)

	// save the cert, in case of installation failure
	account.Certs[mainDomain.Domain] = cert
	if _, err = cl.SetNVData(common.NVDatastoreName, account); err != nil {
		return TS("Unable to store retrieved ssl certificate in nvdata"), err
	}

	issuerCert := strings.ReplaceAll(cert.BestIssuer(preferredIssuerCN)+"\n"+common.CABundle, "\n\n", "\n")

	// install cert
	install, err := cl.InstallSSLKey(cert.Domain, cert.DomainCert, cert.DomainKey, issuerCert)
	if err != nil {
		return TS("Installing ssl certificate"), err
	}

	// update cert with installed ids
	cert.KeyId = install.Data.KeyId
	cert.CertId = install.Data.CertId
	if _, err = cl.SetNVData(common.NVDatastoreName, account); err != nil {
		return TS("Unable to update installed ssl certificate in nvdata"), err
	}

	reuseTargets := account.GetReuseTargetsForSource(cert.Domain)
	for _, target := range reuseTargets {
		if _, err := cl.InstallSSLKey(target, cert.DomainCert, cert.DomainKey, issuerCert); err != nil {
			log.WithError(err).
				WithField("source", cert.Domain).
				WithField("target", target).
				Warn("Unable to install certificate from source onto reuse targetß")
		}
	}

	return install.Data.Message, nil
}

type issueCertificateRequest struct {
	// VirtualHost is the destination virtualhost for this certificate
	VirtualHost string `json:"virtual_host"`
	// DNSIdentifiers is the list of domain names that should be included on the certificate
	DNSIdentifiers []string `json:"dns_identifiers"`
	// ChallengeMethod is the ACME validation method (either dns-01 or http-01)
	ChallengeMethod string `json:"challenge_method"`
	// PreferredIssuerCN is the issuer to prefer, if alternates certificate chains are available.
	PreferredIssuerCN string `json:"preferred_issuer_cn"`
	// DryRun will cause the certificate to be issued by the Let's Encrypt staging server
	// and discarded. It exists to allow testing issuance without wasting rate limits or
	// affecting the live virtual host.
	DryRun bool `json:"dry_run"`
	// What private key type to use for this certificate. Format: rsa:2048 or ecdsa:p-256.
	KeyType string `json:"key_type"`
}

// Equivalent of action=issue
func (h apiHandler) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var req issueCertificateRequest
	if err := processAPIRequestBody(w, r, &req); err != nil {
		return
	}

	if req.VirtualHost == "" {
		serveAPIError(w, http.StatusBadRequest, "The destination `virtual_host` must be provided")
		return
	}
	if len(req.DNSIdentifiers) == 0 {
		serveAPIError(w, http.StatusBadRequest, "At least one DNS identifier (`dns_identifiers`) must be included on the certificate")
		return
	}
	challengeMethods, _ := client.GetChallengeMethods()
	if !common.ArrayProperSubset([]string{req.ChallengeMethod}, challengeMethods) {
		serveAPIError(w, http.StatusBadRequest, fmt.Sprintf("`challenge_method` must be one of: %v", challengeMethods))
		return
	}

	params := client.GetCryptoParams()
	if req.KeyType == "" {
		req.KeyType = params.String()
	}

	// Gather up data from the cPanel account required to issue the certificate
	// NVData
	nvdata, err := common.GetAndParseNVData(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to get account nvdata", err.Error())
		return
	}
	// DomainList
	domains, err := common.GetDomainList(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to fetch account domains", err.Error())
		return
	}

	// Need to pick out the Main Domain from the domain list
	var mainDomain common.DomainEntry
	for _, d := range domains {
		if d.Domain == req.VirtualHost {
			mainDomain = d
			break
		}
	}
	if mainDomain.Domain != req.VirtualHost {
		serveAPIError(w, http.StatusInternalServerError,
			fmt.Sprintf("The virtual host `%s` was not found in the cPanel account", req.VirtualHost))
		return
	}

	// We need to generate an ACME account key if we don't have one already
	if len(nvdata.AccountKey) == 0 {
		if err := common.CreateAccountKey(nvdata, h.cpanelAPI, params); err != nil {
			serveAPIError(w, http.StatusInternalServerError,
				"Failed to generate private key for new ACME account", err.Error())
			return
		}
	}

	keyParams, err := client.KeyTypeStringToParams(req.KeyType)
	if err != nil {
		serveAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ready to issue and install the certificate
	msg, err := issueCertificate(
		nvdata, req.DNSIdentifiers, mainDomain, h.cpanelAPI,
		req.ChallengeMethod, req.PreferredIssuerCN, req.DryRun, keyParams,
	)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to issue certificate", err.Error())
		return
	}

	serveAPISuccess(w, http.StatusOK, msg)
}

type reuseCertificateRequest struct {
	DestinationVirtualHost string `json:"dest_virtual_host"`
	SourceVirtualHost      string `json:"src_virtual_host"`
}

func (h apiHandler) reuseCertificate(w http.ResponseWriter, r *http.Request) {
	var req reuseCertificateRequest
	if err := processAPIRequestBody(w, r, &req); err != nil {
		return
	}

	if req.DestinationVirtualHost == "" || req.SourceVirtualHost == "" {
		serveAPIError(w, http.StatusBadRequest, "Both `src_virtual_host` and `dest_virtual_host` must be provided")
		return
	}

	nvdata, err := common.GetAndParseNVData(h.cpanelAPI)
	if err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to get account nvdata", err.Error())
		return
	}

	if err := common.MapCertificateReuse(h.cpanelAPI, nvdata, req.SourceVirtualHost, req.DestinationVirtualHost); err != nil {
		serveAPIError(w, http.StatusInternalServerError, "Failed to apply certificate re-use", err.Error())
		return
	}

	serveAPISuccess(w, http.StatusOK, nil)
}
