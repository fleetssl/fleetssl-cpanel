package daemon

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"

	"encoding/json"
	"encoding/pem"

	"bufio"
	"io"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"github.com/letsencrypt-cpanel/cpanelgo/whm"
)

const (
	ResultRenewalSuccess = iota
	ResultRenewalFail
	ResultRenewalReinstall
)

type RenewalResult int

func shouldRunRenewals(now time.Time) bool {
	shouldRun := true

	if config.RenewalDaysOfWeek != nil {
		shouldRun = false

		today := strings.ToLower(now.Weekday().String())
		for _, d := range config.RenewalDaysOfWeek {
			if strings.ToLower(d) == today {
				shouldRun = true
				break
			}
		}
	}

	if config.RenewalTimeOfDay != nil {
		shouldRun = now.Hour() >= config.RenewalTimeOfDay[0] &&
			now.Hour() <= config.RenewalTimeOfDay[1]
	}

	return shouldRun
}

func processRenewals(exitCh chan<- error) { // blocking
	for {
		if !shouldRunRenewals(time.Now()) {
			log.WithField("days", config.RenewalDaysOfWeek).
				WithField("hours", config.RenewalTimeOfDay).
				Debug("Deferring renewals for 1 hour as we are outside configured schedule")
			time.Sleep(1 * time.Hour)
			continue
		}

		log.Info("Processing renewals")

		accts, err := whmCl.ListAccounts()
		if err != nil {
			log.WithError(err).Error("Failed to fetch accounts, will try again in 1 minute")

			time.Sleep(1 * time.Minute)
			continue
		}

		autosslCandidates := []string{}

		restartApacheIfNecessary()

		nextRestart := time.Now().Add(time.Hour)

		// First do renewals
		for _, acct := range accts.Data.Accounts {
			if acct.User == "" || acct.User == "root" {
				continue
			}

			_, err := processRenewalsForAccount(whmCl, acct.User, false, false, "")
			if err != nil {
				log.WithError(err).WithField("User", acct.User).Error("Failed to process renewals")
			}
			if config.AutoSSL {
				autosslCandidates = append(autosslCandidates, acct.User)
			}
			time.Sleep(time.Duration(*config.PerAccountDelay) * time.Second)

			if time.Now().After(nextRestart) {
				nextRestart = time.Now().Add(time.Hour)
				restartApacheIfNecessary()
				time.Sleep(time.Duration(*config.PerAccountDelay) * time.Second) // probably not necessary, but just in case
			}
		}
		log.Info("Finished processing renewals")

		// call the post renewal hook, post loop
		if hookErr := postRenewalHook(postRenewalHookInfo{
			Success: true,
		}); hookErr != nil {
			log.WithError(hookErr).Warn("Error running post loop postRenewalHook")
		}

		restartApacheIfNecessary()

		// Then do AutoSSL
		if config.AutoSSL {
			// even through autosslCandidates should always be empty when autossl is disabled,
			// this guard just stops logging msgs about it
			log.Info("Starting AutoSSL processing ...")
			for _, un := range autosslCandidates {
				// TODO: check rate limits before each one

				if _, _, err := processAutoSSLForAccount(un, nil, false); err != nil {
					log.WithError(err).WithField("Username", un).Error("Failed to process AutoSSL")
				}
				time.Sleep(time.Duration(*config.PerAccountDelay) * time.Second)
			}

			if len(autosslCandidates) > 0 {
				restartApacheIfNecessary()
			}

			log.Info("Finished processing scheduled AutoSSL")
		}

		time.Sleep(RenewalsInterval * time.Hour)
	}
}

func processRenewalsForAccount(whmCl whm.WhmApi, username string, forceRenewals, dryRun bool, onlyThisVirtualHost string) (map[string]*common.NVDataDomainCerts, error) {
	if !lockUser(username) {
		return nil, fmt.Errorf("User %s has an open lock", username)
	}
	defer unlockUser(username)

	l := log.WithFields(log.Fields{
		"Function": "processRenewalsForAccount",
		"Username": username,
	})

	cp, err := makeCpanelClient(username)
	if err != nil {
		return nil, errors.New("Making cpanel impersonation client: " + err.Error())
	}

	data, err := common.GetAndParseNVData(cp)
	if err != nil {
		return nil, errors.New("parsing nvdata: " + err.Error())
	}

	accountSummary, err := whmCl.AccountSummary(username)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch account summary: %v", err)
	}

	if err := accountPreflight(username, accountSummary, cp, data); err == errNoFeature || err == errAccountSuspended {
		return nil, fmt.Errorf("User %s not eligible for renewal: %v", username, err)
	} else if err != nil {
		return nil, fmt.Errorf("Fatal pre-flight failure for renewal for %s: %v", username, err)
	}

	if data.Certs == nil || len(data.Certs) == 0 {
		return nil, nil
	}

	if !dryRun {
		if err := common.CleanupOldCerts(username, cp, data, 5); err != nil {
			l.WithError(err).Warn("Failed to clean up old certificates pre-renewal")
		}
	}

	// get the users domains
	allDomains, err := common.GetDomainList(cp)
	if err != nil {
		return nil, err
	}

	// Add all the proxy subdomains for all vhosts
	proxyLabels, err := common.GetProxyDomainLabels(username, cp)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch available proxy subdomains: %v", err)
	}
	for pxd, entry := range allDomains {
		for _, d := range proxyLabels {
			allDomains.AddDomain(fmt.Sprintf("%s.%s", d, pxd), "Proxy", entry.DocumentRoot, entry.User, entry.DomainRoot)
		}
	}

	updatedCerts := map[string]*common.NVDataDomainCerts{}

	// ignore expiry dates if env var present
	if !forceRenewals && os.Getenv("LE_FORCE_RENEWALS") == "1" {
		forceRenewals = true
	}

	locale := "en"
	localeAttribs, lerr := cp.GetUserLocale()
	if lerr != nil {
		l.WithError(lerr).Error("Failed to get locale, defaulting to english")
	} else if len(localeAttribs.Data) == 0 {
		l.Warn("No locale provided, defaulting to english")
	} else {
		locale = localeAttribs.Data[0].Locale
	}

	doEmail := func(template string, args MailArgs) error {
		if config.DisableRenewalMail || data.DisableMail || dryRun {
			// don't send email if globally disabled or used has disabled, or if it's a dry-run
			return nil
		}
		_, hasError := args["Error"]
		if config.DisableSuccessMail && !hasError {
			// don't send email if success is disabled and there's no error (assume success == no error)
			return nil
		}

		// anti spam by domain
		if domain, ok := args["Domain"]; ok && hasError {
			var lastErrorTime int64
			if err := dbFetchBucket("failure_emails", domain.(string), &lastErrorTime); err != nil {
				log.WithError(err).WithField("domain", domain).Warn("Failed to check failure_emails")
			} else if lastErrorTime > 0 && time.Since(time.Unix(lastErrorTime, 0)) < (48*time.Hour) {
				log.WithField("domain", domain).Info("Inhibiting failure email")
				return nil
			}
			dbPutBucket("failure_emails", domain.(string), time.Now().Unix())
		}

		var dest string
		if accountSummary.HasEmail() {
			dest = strings.TrimSpace(accountSummary.Email())
		}
		if dest == "" {
			// no destination email provided, no need to send email or return error
			return nil
		}
		tpl, terr := GetMailTemplate(locale, template)
		if terr != nil {
			return fmt.Errorf("Error getting mail template for user %s - %v", username, terr)
		}
		return SendMail(dest, tpl.Subject, tpl.Body, tpl.Html, args, whmCl.Insecure)
	}

	// Gather up all of the wanted SSL names
	// and group them according to the DomainsData
	// This shall form the source of truth for issuing
	//
	// If creating this structure fails, then we need to notify
	// the user or server admin.
	groupedDomains, leftovers, err := common.GroupNVDataDomains(data.Certs, allDomains)
	if err != nil {
		addReport(report{
			IsFailure: true,
			User:      username,
			Message:   fmt.Sprintf("Failed to group domains: %v", err.Error()),
			When:      time.Now(),
		})
		if mailErr := doEmail(MailTemplatePreError, MailArgs{
			"Account": username,
			"Action":  "Failed to group domains for renewal",
			"Error":   err.Error(),
		}); mailErr != nil {
			l.WithError(mailErr).Error("Sending mail")
		}
		return nil, fmt.Errorf("Failed to group domains: %v", err)
	}

	if len(leftovers) > 0 {
		l.WithField("leftovers", leftovers).
			Warn("There were a number of domains that could not be linked to any virtual host." +
				" They have been removed from the this and future certificate renewals.")
	}

	sslHosts, err := cp.InstalledHosts()
	if err != nil {
		if !dryRun {
			addReport(report{
				IsFailure: true,
				User:      username,
				Message:   fmt.Sprintf("Failed to fetch installed SSL hosts: %v", err.Error()),
				When:      time.Now(),
			})
		}
		if mailErr := doEmail(MailTemplatePreError, MailArgs{
			"Account": username,
			"Action":  "Failed to fetch installed ssl hosts",
			"Error":   err.Error(),
		}); mailErr != nil {
			l.WithError(mailErr).Error("Sending mail")
		}
		return nil, fmt.Errorf("Failed to fetch account's ssl hosts: %v", err)
	}

	// check any certs that list "not installed" after "unknown error" renewal
	foundCertInstalled := false
	if !dryRun {
		for savedDomain, savedCert := range data.Certs {
			// for each installed cert
			if savedCert.CertId == "" {
				// check if it has no cert id (eg, "not installed")
				cert, err := common.DecodeToCert(savedCert.DomainCert)
				if err != nil {
					continue
				}
				// try to find an existing one in the installed certs
				for _, h := range sslHosts.Data {
					c, err := common.DecodeToCert(h.CertificateText)
					if err != nil {
						continue
					}
					// if found by serial number, set the certid
					if cert.SerialNumber.Cmp(c.SerialNumber) == 0 {
						l.WithField("domain", savedDomain).Println("Setting installed status")
						savedCert.CertId = h.Certificate.Id
						foundCertInstalled = true
					}
				}
			}
		}
	}

	// Filter sslHosts by removing any Let's Encrypt certificates which produce
	// an OCSP revoked response
	var sslHostsUnrevoked cpanel.InstalledHostsApiResponse
	if sslHostsUnrevoked, err = filterRevokedCertificates(sslHosts, data); err != nil {
		l.WithError(err).Warn("Failed to check installed certificate revocations")
	}

	// Remove any groups from the map that already have certificates
	// that are not expiring/expired, not self-signed, and contain
	// all of the names required by the group
	if !forceRenewals && !dryRun {
		cutoff := time.Now().Add(time.Duration(config.RenewalCountdownDays) * 24 * time.Hour)
		for rootDomain, group := range groupedDomains {
			keep := false
			for _, domain := range group {
				// We don't have a cert for this SAN, issue!
				if !sslHostsUnrevoked.HasValidDomain(domain.Domain, cutoff) {
					keep = true
				}
			}

			if !keep {
				delete(groupedDomains, rootDomain)
			}
		}
	}

	// Everything we have left over in groupedDomains needs to be issued.
	for root, group := range groupedDomains {
		dl := l.WithField("Root", root)

		if onlyThisVirtualHost != "" && onlyThisVirtualHost != root {
			continue
		}

		domainNames := group.GatherNames()
		dl = dl.
			WithField("domains", strings.Join(domainNames, ",")).
			WithField("domain", root)

		dl.Info("Is up for renewal")

		// Inhibit renewal attempts for long-failing domains
		var ras renewalAttemptState
		if err := dbFetchBucket("renewal_attempts", root, &ras); err != nil {
			dl.Warn("Failed to check renewal inhibition")
		} else if !forceRenewals && !dryRun && !ras.IsZero() && ras.Attempts > 10 {
			lastAttemptTime := time.Unix(ras.LastAttempt, 0)
			penalty := (12 * time.Hour) * time.Duration(math.Max(0, float64(ras.Attempts)-10))
			// Cap out at 1 week. This means that if the certificate is re-issued via the UI,
			// we will still renew it in time and the penalty will reset.
			if penalty > (168 * time.Hour) {
				penalty = 168 * time.Hour
			}
			if time.Now().Before(lastAttemptTime.Add(penalty)) {
				dl.WithFields(log.Fields{
					"attempts":     ras.Attempts,
					"last_attempt": lastAttemptTime,
					"penalty":      penalty,
					"last_error":   ras.LastError,
				}).Info("Inhibiting renewal attempt until a later time due too many failures")
				continue
			}
		}

		// process the renewal for the domain on the account
		cert, result, err := processRenewalForAccountDomain(root, username, group, data, cp, dryRun, forceRenewals)

		if !dryRun {
			// If no error was experienced, then we write a fresh RAS
			if err == nil {
				ras.Attempts = 0
				ras.LastError = ""
			} else {
				ras.LastError = err.Error()
			}
			// Increment the RAS irrespective of result
			ras.Root = root
			ras.Attempts = ras.Attempts + 1
			ras.LastAttempt = time.Now().Unix()
			// And persist it
			if err := dbPutBucket("renewal_attempts", root, ras); err != nil {
				dl.WithError(err).Error("Failed to write new renewal attempt state")
			}
		}

		if cert == nil {
			dl.Warn("cert was nil after processRenewalForAccountDomain. This SHOULD NOT HAPPEN. CONTACT SUPPORT")
			continue
		}

		if !dryRun {
			// call the post renewal hook
			if hookErr := postRenewalHook(postRenewalHookInfo{
				Account: username,
				Domains: domainNames,
				Success: !(err != nil || result == ResultRenewalFail),
				Error: func() string {
					if err == nil {
						return ""
					}
					return err.Error()
				}(),
				Certificate: cert.DomainCert,
				Issuer:      cert.IssuerCert,
				Key:         cert.DomainKey,
			}); hookErr != nil {
				dl.WithError(hookErr).Warn("Error running postRenewalHook")
			}
		}

		// handle the error from processRenewalForAccountDomain
		if err != nil || result == ResultRenewalFail {
			// this shouldn't happen, an error should always be returned when result == ResultRenewalFail (but just in case)
			if err == nil {
				err = errors.New("Unknown error, please contact support.")
			}
			if !dryRun {
				addReport(report{
					IsFailure: true,
					User:      username,
					Domain:    root,
					Message:   fmt.Sprintf("Failed to renew: %v", err.Error()),
					When:      time.Now(),
				})
			}

			// Log reason for renewal failure with as much detail as possible
			dl.
				WithFields(log.Fields{
					"groupedDomains": groupedDomains,
					"leftovers":      leftovers,
				}).
				WithError(err).
				Error("Error renewing")

			// send failure email
			if mailErr := doEmail(MailTemplateFailure, MailArgs{
				"Domain": root,
				"Expiry": time.Unix(cert.CertExpiry, 0).String(),
				"Error":  err,
			}); mailErr != nil {
				dl.WithError(mailErr).Error("Failed to send renewal error mail")
			}

			// continue with next domain
			continue
		}

		dl.Info("Successfully renewed")

		time.Sleep(time.Second)

		if !dryRun {
			addReport(report{
				IsFailure: false,
				User:      username,
				Domain:    root,
				Message:   "Renewed",
				When:      time.Now(),
			})
		}
		if result != ResultRenewalReinstall {
			// send success email
			if mailErr := doEmail(MailTemplateSuccess, MailArgs{
				"Domain": root,
				"Expiry": time.Unix(cert.CertExpiry, 0).String(),
			}); mailErr != nil {
				dl.WithError(mailErr).Error("Failed to send renewal success mail")
			}
		}
		// store the cert in the updatedcerts map for storing in nvdata
		updatedCerts[root] = cert
	}

	if !dryRun {
		// Replace all the certificates in the NVData
		data.LastRenewalCheck = time.Now().Unix()
		for d, v := range updatedCerts {
			data.Certs[d] = v
		}
	}

	// only set nvdata if we updated any certs and it's not a dry-run
	if (len(updatedCerts) > 0 || foundCertInstalled) && !dryRun {
		if _, nvdataErr := cp.SetNVData(common.NVDatastoreName, data); nvdataErr != nil {
			l.WithError(nvdataErr).Error("Failed to set account nvdata")
			addReport(report{
				IsFailure: true,
				User:      username,
				Message:   fmt.Sprintf("Failed to save nvdata: %v", nvdataErr.Error()),
				When:      time.Now(),
			})
			if mailErr := doEmail(MailTemplateNvdataError, MailArgs{
				"Error": nvdataErr.Error(),
			}); mailErr != nil {
				l.WithError(err).Error("Failed to send NVData failure email")
			}
			return nil, nvdataErr
		}
	}

	return updatedCerts, nil
}

// renews a domain certificate on an account
// returns newcert on success, existingcert on failure
func processRenewalForAccountDomain(root, username string, group common.DomainList,
	data *common.NVDataAccount, cp cpanel.CpanelApi,
	dryRun, forceRenewals bool) (*common.NVDataDomainCerts, RenewalResult, error) {
	// get/create existing cert from nvdata
	existingCert, err := getExistingCertificateFromNVData(root, group, data)
	if err != nil {
		return existingCert, ResultRenewalFail, fmt.Errorf("Unable to get certificate from nvdata: %v", err)
	}

	docroot := ""
	for _, v := range group {
		docroot = v.DocumentRoot
		break
	}
	if docroot == "" {
		return existingCert, ResultRenewalFail,
			errors.New("Unable to determine document root for this domain - please re-issue certificate from web interface")
	}

	var newCert *common.NVDataDomainCerts

	// If we already have a valid certificate for this domain, and it's being renewed for some reason,
	// reuse it, instead of issuing a new one. (Unless dry-run or --force).
	if !dryRun && !forceRenewals {
		// 1. The expiry must be sufficiently far away
		cutoff := time.Now().Add(time.Duration(config.RenewalCountdownDays) * 24 * time.Hour)
		hasEnoughValidity := time.Unix(existingCert.CertExpiry, 0).After(cutoff)
		// 2. The certificate must not be revoked
		isRevoked, _ := isCertificateRevokedOCSP(existingCert.DomainCert, existingCert.IssuerCert)

		if hasEnoughValidity && !isRevoked {
			log.WithField("domain", root).Info("Re-using existing certificate in storage, not renewing")
			newCert = existingCert
		}
	}

	// get the new renewed certificate
	if newCert == nil {
		newCert, err = getRenewedCert(existingCert, data.AccountKey, username, docroot, cp, dryRun)
		if err != nil {
			return existingCert, ResultRenewalFail, fmt.Errorf("Unable to renew certificate: %v", err)
		}
	}

	// During a dry-run, we don't want to install or do the other remainder of tasks
	if dryRun {
		return newCert, ResultRenewalSuccess, nil
	}

	// install the new certificate
	// (this is actually feature flagged within the function config.DeferredRestarts)
	installed, err := installCertNoRestart(cp, root, time.Unix(newCert.CertExpiry, 0), newCert)
	if err != nil {
		return newCert, ResultRenewalFail, fmt.Errorf("Unable to install certificate: %v", err)
	}
	newCert.CertId = installed.Data.CertId
	newCert.KeyId = installed.Data.KeyId

	// Also install the certificate to every vhost that reuses it, ignoring errors
	for _, reuse := range data.GetReuseTargetsForSource(root) {
		log.WithField("domain", root).WithField("reuse", reuse).Info("Installing certificate (re-use)")
		if _, err := installCertNoRestart(cp, reuse, time.Unix(newCert.CertExpiry, 0), newCert); err != nil {
			log.WithError(err).WithField("domain", root).WithField("reuse", reuse).Error("Failed to install certificate for re-use")
		}
	}

	// delete existing cert&key, ignoring any errors
	if existingCert.CertId != "" {
		_, _ = cp.DeleteCert(existingCert.CertId)
	}
	if existingCert.KeyId != "" {
		_, _ = cp.DeleteKey(existingCert.KeyId)
	}

	var result RenewalResult = ResultRenewalSuccess
	if newCert == existingCert {
		result = ResultRenewalReinstall
	}

	return newCert, result, nil
}

func getExistingCertificateFromNVData(root string, group common.DomainList, data *common.NVDataAccount) (*common.NVDataDomainCerts, error) {
	existingCert, ok := data.Certs[root]
	// We may need to create the map entry from scratch
	if !ok {
		// create a private key
		cryptoParams := client.GetCryptoParams()
		key, err := common.DefaultPrivateKey(cryptoParams)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate new key: %v", err)
		}
		// create the certificate
		domainNames := group.GatherNames()
		existingCert = &common.NVDataDomainCerts{
			Domain:    domainNames[0],
			AltNames:  domainNames[1:],
			DomainKey: key.AsPEM(),
		}
	}
	// Always set AltNames
	existingCert.AltNames = group.GatherNames()
	return existingCert, nil
}

func getRenewedCert(certData *common.NVDataDomainCerts, accountKeyPem, username, docroot string, cp cpanel.CpanelApi, dryRun bool) (*common.NVDataDomainCerts, error) {
	// for each domain and altname
	domains := []string{certData.Domain}
	if len(certData.AltNames) > 0 {
		domains = append(domains, certData.AltNames...)
	}

	method := certData.ChallengeMethod
	if method == "" {
		method = "http-01"
	}

	preferredIssuer := certData.PreferredIssuer
	if preferredIssuer == "" {
		preferredIssuer = config.PreferredIssuerCN
	}

	cert, err := common.RequestCert(common.CertificateRequest{
		AccountKeyPEM:        accountKeyPem,
		Domains:              domains,
		DocRoots:             []string{docroot},
		Method:               method,
		CpanelAPI:            cp,
		DropPrivilegesToUser: username,
		PKF:                  common.PrivateKeyFromPem(certData.DomainKey),
		PreferredIssuer:      preferredIssuer,
		DryRun:               dryRun,
	})
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func installCertNoRestart(cp cpanel.CpanelApi, domain string, expiry time.Time, crt *common.NVDataDomainCerts) (cpanel.InstallSSLKeyAPIResponse, error) {
	l := log.WithFields(log.Fields{
		"Function": "installCertNoRestart",
		"Domain":   domain,
	})

	if config.DeferredRestarts {
		// Only skip apache restart if expiry is at least 12 hours away
		if !expiry.IsZero() && expiry.After(time.Now().Add(12*time.Hour)) {
			l.Info("This SSL installation will not trigger an immediate apache restart and the certificate may take some time to become active")

			flagTimeout := time.Now().Add(1 * time.Minute).Unix()

			if err := requestSetFlag(cpanelFlagFileDontRestartApache, flagTimeout); err != nil {
				l.WithError(err).Error("Failed to request no restart flag")
			}
			if err := dbPutBucket("state", "httpd_needs_restart", "yes"); err != nil {
				l.WithError(err).Error("Failed to persist restart state")
			}

			defer func() {
				if err := requestUnsetFlag(cpanelFlagFileDontRestartApache, flagTimeout); err != nil {
					l.WithError(err).Error("Failed to unset no restart flag")
				}
			}()

		} else {
			l.Info("This renewal will trigger an apache restart because expiry is within 12 hours")
		}
	}

	preferredIssuerOrDefault := crt.PreferredIssuer
	if preferredIssuerOrDefault == "" {
		preferredIssuerOrDefault = config.PreferredIssuerCN
	}
	issuerCert := strings.ReplaceAll(crt.BestIssuer(preferredIssuerOrDefault)+"\n"+common.CABundle, "\n\n", "\n")

	return cp.InstallSSLKey(domain, crt.DomainCert, crt.DomainKey, issuerCert)
}

func restartApacheIfNecessary() {
	// Graceful restart apache if necessary
	var needsRestart string
	if err := dbFetchBucket("state", "httpd_needs_restart", &needsRestart); err != nil {
		log.WithError(err).Error("Failed to fetch httpd_needs_restart state")
		return
	}

	if needsRestart == "yes" {
		defer func() {
			// we only should try restart once, so unset the flag immediately
			if err := dbPutBucket("state", "httpd_needs_restart", "no"); err != nil {
				log.WithError(err).Error("Failed to set httpd_needs_restart to no")
			}
		}()

		restartApache()
	}
}

func restartApache() {
	log.Info("Graceful restarting apache")
	if err := exec.Command("/scripts/restartsrv_httpd").Run(); err != nil {
		log.WithError(err).Error("Failed to graceful restart apache")
	}
}

type postRenewalHookInfo struct {
	Account     string
	Domains     []string
	Success     bool
	Error       string
	Certificate string
	Issuer      string
	Key         string
}

func postRenewalHook(info postRenewalHookInfo) error {
	if config.HookPostRenewal == "" {
		return nil
	}

	stat, err := os.Stat(config.HookPostRenewal)
	if os.IsNotExist(err) {
		return nil
	}

	if stat.IsDir() {
		return errors.New("Hook should be an absolute path to a file")
	}

	if uint32(stat.Mode().Perm()) != 0700 {
		return errors.New("Hook file mode must be 0700")
	}

	b, err := json.Marshal(&info)
	if err != nil {
		return fmt.Errorf("Error marshalling hook info: %v", err)
	}

	cmd := exec.Command(config.HookPostRenewal)

	if stdout, err := cmd.StdoutPipe(); err == nil {
		defer stdout.Close()
		logReader("postRenewalHook", log.InfoLevel, stdout)
	}
	if stderr, err := cmd.StdoutPipe(); err == nil {
		defer stderr.Close()
		logReader("postRenewalHook", log.ErrorLevel, stderr)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("Error opening pipe to post hook: %v", err)
	}
	defer stdin.Close()

	if _, err := stdin.Write(b); err != nil {
		return fmt.Errorf("Error piping to post hook: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Error starting post hook: %v", err)
	}

	return nil
}

func logReader(source string, level log.Level, r io.ReadCloser) {
	l := log.WithField("Source", source)
	scanner := bufio.NewScanner(r)
	go func() {
		for scanner.Scan() {
			t := scanner.Text()
			if t == "" {
				continue
			}
			if level == log.ErrorLevel {
				l.Error(t)
			} else {
				l.Info(t)
			}
		}
	}()
}

func filterRevokedCertificates(sslHosts cpanel.InstalledHostsApiResponse, data *common.NVDataAccount) (cpanel.InstalledHostsApiResponse, error) {
	var filtered []cpanel.InstalledCertificate

	findCertByID := func(id string) *common.NVDataDomainCerts {
		for _, nvCert := range data.Certs {
			if nvCert.CertId == id {
				return nvCert
			}
		}
		return nil
	}

	for _, host := range sslHosts.Data {
		cert := findCertByID(host.Certificate.Id)
		// If we don't know about the certificate in the nvdata, then we can ignore the certificate
		if cert == nil {
			filtered = append(filtered, host)
			continue
		}

		revoked, err := isCertificateRevokedOCSP(cert.DomainCert, cert.IssuerCert)
		// If we failed the check the revocation status, we can ignore the certificate
		if err != nil {
			log.WithError(err).WithField("cert_id", cert.CertId).Warn("Failed to check revocation of certificate, will assume not revoked")
			filtered = append(filtered, host)
			continue
		}

		// If the certificate is revoked, then we need to filter it out
		if revoked {
			log.WithField("cert_id", cert.CertId).Warn("Certificate is revoked, will consider it invalid when checking renewals")
			continue
		}

		filtered = append(filtered, host)
	}

	return cpanel.InstalledHostsApiResponse{Data: filtered}, nil
}

func isCertificateRevokedOCSP(leafPEM string, issuerPEM string) (bool, error) {
	leafDER, _ := pem.Decode([]byte(leafPEM))
	if leafDER == nil {
		return false, nil
	}
	leaf, err := x509.ParseCertificate(leafDER.Bytes)
	if err != nil {
		return false, err
	}

	issuerDER, _ := pem.Decode([]byte(issuerPEM))
	if issuerDER == nil {
		return false, nil
	}
	issuer, err := x509.ParseCertificate(issuerDER.Bytes)
	if err != nil {
		return false, err
	}

	if len(leaf.OCSPServer) < 1 {
		return false, fmt.Errorf("unexpected number of OCSP URLs: %v", leaf.OCSPServer)
	}

	ocspURL, err := url.Parse(leaf.OCSPServer[0])
	if err != nil {
		return false, err
	}

	ocspReqBuf, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest(http.MethodPost, ocspURL.String(), bytes.NewReader(ocspReqBuf))
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	req.Header.Set("content-type", "application/ocsp-request")
	req.Header.Set("accept", "application/ocsp-response")
	req.Header.Set("user-agent", "fleetssl-cpanel/"+common.AppVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	respBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	ocspResp, err := ocsp.ParseResponse(respBuf, issuer)
	if err != nil {
		return false, err
	}

	return ocspResp.Status == ocsp.Revoked, nil
}
