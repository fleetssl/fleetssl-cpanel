package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/juju/ratelimit"
	log "github.com/sirupsen/logrus"

	"regexp"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
	"github.com/boltdb/bolt"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"github.com/letsencrypt-cpanel/cpanelgo/whm"
)

// gatherAccessibleDomains generates a list of domains that satisfy all of:
//  1. Would pass DCV
//  2. Do not already have a valid SSL certificate installed on the
//     virtual host that owns the domain
func gatherAccessibleDomains(username string, cp cpanel.CpanelApi,
	wantedNames []string) (common.DomainList, map[string]string, error) {
	debug := map[string]string{}

	l := log.WithFields(log.Fields{
		"Function":    "gatherAccessibleDomains",
		"Username":    username,
		"WantedNames": wantedNames,
	})
	accessible := common.DomainList{}

	// Gather domains data, including:
	// - Main, Addon and Subdomains
	// - Alias Domains
	// - Proxy subdomains
	//
	domains, err := common.GetDomainList(cp)
	if err != nil {
		return nil, debug, err
	}
	// Add proxy subdomains as well
	if !config.AutoSSLSkipProxy {
		proxyLabels, err := common.GetProxyDomainLabels(username, cp)
		if err != nil {
			l.WithError(err).Warn("Failed to gather proxy subdomains")
		}
		for pxd, entry := range domains {
			// Only some cPanel domain types are eligible to have proxy subdomains
			if entry.DomainType != "Main" &&
				entry.DomainType != "Addon" &&
				entry.DomainType != "Alias" &&
				entry.DomainType != "Addon Alias" {
				continue
			}
			// Special-case exclude www. and mail. since they are cPanel default built-in alias domains that
			// can't have proxy subdomains ever
			if strings.HasSuffix(entry.DomainType, "Alias") && (strings.HasPrefix(pxd, "www.") || strings.HasPrefix(pxd, "mail.")) {
				continue
			}

			for _, d := range proxyLabels {
				domains.AddDomain(fmt.Sprintf("%s.%s", d, pxd), "Proxy", entry.DocumentRoot, entry.User, entry.DomainRoot)
			}
		}
	}

	// Cheapest thing to filter out is anything outside of wantedNames, do that first
	if len(wantedNames) > 0 {
		for domain, entry := range domains {
			skip := true
			for _, name := range wantedNames {
				if common.NormalizeDomain(name) == common.NormalizeDomain(entry.Domain) {
					skip = false
				}
			}
			if skip {
				domains.RemoveDomain(domain)
				debug[entry.Domain] = fmt.Sprintf("Excluded domain because wantedNames were "+
					"specified (%v) and it didn't match", wantedNames)
			}
		}
	}

	// Now we have all the combinations to try, filter any domains for which
	// there is already an SSL certificate on the virtual host installed
	sslHosts, err := cp.InstalledHosts()
	if err != nil {
		return nil, debug, fmt.Errorf("Failed to list installed ssl hosts: %v", err)
	}
	cutoff := time.Now().Add(time.Duration(config.AutoSSLReplacementCutoff*24) * time.Hour)
	for domain, entry := range domains {
		if sslHosts.HasValidDomain(entry.DomainRoot, cutoff) ||
			sslHosts.HasValidDomain(entry.Domain, cutoff) ||
			sslHosts.DoesAnyValidCertificateOverlapVhostsWith(entry.Domain, cutoff) ||
			sslHosts.DoesAnyValidCertificateOverlapVhostsWith(entry.DomainRoot, cutoff) {
			debug[domain] = fmt.Sprintf("Excluded (domain %s, virtual host %s) due to existing "+
				"certificate (not expiring within %d days).",
				entry.Domain, entry.DomainRoot, config.AutoSSLReplacementCutoff)
			domains.RemoveDomain(domain)
		}
	}

	start := time.Now()

	// First we need to test each DomainRoot, because the plugin
	// relies on the DomainRoot as being part of every certificate
	workingDomainRoots := map[string]bool{}
	for _, v := range domains {
		// Only check DomainRoots
		if v.Domain != v.DomainRoot {
			continue
		}
		// Only check once
		if _, exists := workingDomainRoots[v.DomainRoot]; !exists {
			// Skip if its already too many attempts under this DomainRoot
			var autosslRas renewalAttemptState
			if err := dbFetchBucket("autossl_attempts", v.DomainRoot, &autosslRas); err != nil && autosslRas.Attempts > 10 {
				debug[v.DomainRoot] = "Excluded virtual host because too many attempts failed for it recently"
				continue
			}
			// Otherwise check accessibility
			if err := common.IsDomainAccessible(username, v, cp); err != nil {
				debug[v.Domain] = fmt.Sprintf("Excluded domain because DCV test failed (%v)", err)
				workingDomainRoots[v.DomainRoot] = false
				// We need to remember only if the DomainRoot fails
				autosslRas.Attempts++
				autosslRas.Root = v.DomainRoot
				dbPutBucket("autossl_attempts", v.DomainRoot, autosslRas)
			} else {
				debug[v.Domain] = fmt.Sprintf("Included domain because DCV passed")
				workingDomainRoots[v.DomainRoot] = true
			}
		}
	}

	for _, v := range domains {
		skip := false

		for _, toSkip := range config.AutoSSLSkipPatterns {
			d := common.NormalizeDomain(v.Domain)
			if matched, _ := regexp.MatchString(toSkip, d); matched {
				debug[v.Domain] = fmt.Sprintf("Excluded domain because global AutoSSL skip pattern matched")
				l.WithField("Skipped", v.Domain).Info("Skipping domain as per global config regex")
				skip = true
				break
			}
		}

		// Filter for wantedNames
		if len(wantedNames) > 0 {
			found := false
			for _, w := range wantedNames {
				if common.NormalizeDomain(v.Domain) == common.NormalizeDomain(w) {
					found = true
					break
				}
			}
			if !found {
				debug[v.Domain] = fmt.Sprintf("Excluded domain because wantedNames were "+
					"specified (%v) and it didn't match", wantedNames)
				l.WithField("Skipped", v).Println("Skipped because it was not specified")
				skip = true
			}
		}

		// If the domain root doesnt pass, then we ignore all other domains
		// under the same virtualhost
		if workingDomainRoots[v.DomainRoot] == false {
			debug[v.Domain] = fmt.Sprintf("Excluded domain because its associated " +
				" virtual host root did not pass DCV tests")
			skip = true
		}

		if skip {
			continue
		}

		// Try not to DoS the server
		time.Sleep(1 * time.Second)

		// If this domain has been tried too many times, then dont try again
		var autosslRas renewalAttemptState
		if err := dbFetchBucket("autossl_attempts", v.Domain, &autosslRas); err != nil && autosslRas.Attempts > 10 {
			debug[v.Domain] = "Excluded domain because too many attempts failed for it recently"
			l.WithField("domain", v.Domain).Info("Skipping due to too many failed attempts")
			continue
		}

		// check if the domain .well-known is accessible
		if err := common.IsDomainAccessible(username, v, cp); err != nil {
			debug[v.Domain] = fmt.Sprintf("Excluded domain because DCV test failed (%v)", err)
			l.WithField("Domain", v).WithError(err).Debug("Pre-flight check failed")
			// We only need to track failures, not successes
			autosslRas.Attempts++
			autosslRas.Root = v.Domain
			dbPutBucket("autossl_attempts", v.Domain, autosslRas)
			continue
		}

		accessible[v.Domain] = v
		accessible[v.DomainRoot] = v
	}

	if len(accessible) > 0 {
		l.WithField("domains", accessible.GatherNames()).
			WithField("duration", time.Since(start)).
			Info("Gathered accessible domains")
	}

	return accessible, debug, nil
}

var errAccountSuspended = errors.New("Account is suspended")
var errNoFeature = errors.New("Account does not have plugin feature")

var regexOrgName = regexp.MustCompile("Let.?s Encrypt")

func accountPreflight(username string, accountSummary whm.AccountSummaryApiResponse, cp cpanel.CpanelApi, data *common.NVDataAccount) error {
	// skip account if suspended
	if accountSummary.Suspended() {
		return errAccountSuspended
	}

	if message, err := cp.HasFeature("letsencrypt-cpanel"); err != nil {
		// Workaround for broken cPanel 64
		if !strings.Contains(err.Error(), "/var/cpanel/licenseid_credentials.json") {
			return err
		}
	} else if message != "" {
		// dont return an error, as this isn't actually an error
		// return nil as if this had succeeded
		// don't renew this user's certificates if the feature is disabled
		//  (message is not empty when feature is disabled)
		return errNoFeature
	}

	if message, err := cp.HasFeature("sslinstall"); err != nil {
		return err
	} else if message != "" {
		return errNoFeature
	}

	qi, err := cp.GetQuotaInfo()
	if err != nil {
		log.WithError(err).WithField("Username", username).Warn("Failed to fetch quota info")
	} else if !qi.IsUnderQuota() {
		return fmt.Errorf("User is over quota: %s (%v)", username, err)
	}

	return nil
}

// domains may be nil which indicates 'autossl': all domains should try and issue
func processAutoSSLForAccount(username string,
	names []string, retryIfFail bool) (map[string]*common.NVDataDomainCerts, map[string]string, error) {
	if !lockUser(username) {
		return nil, nil, fmt.Errorf("user %s has an open lock", username)
	}
	defer unlockUser(username)

	l := log.WithFields(log.Fields{
		"Function":    "processAutoSSLForAccount",
		"Username":    username,
		"WantedNames": names,
		"Retry":       retryIfFail,
	})

	cp, err := makeCpanelClient(username)
	if err != nil {
		return nil, nil, errors.New("Making cpanel impersonation client: " + err.Error())
	}

	data, err := common.GetAndParseNVData(cp)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse nvdata: %v", err)
	}

	// For AutoSSL, we need to ensure that we do not generate too many registrations,
	// to maximize the chance that users will be able to register certificates and avoid
	// the 10 Accounts Per IP Address per 3 hours rate limit.
	//
	// So, we will rate limit ourselves to 70% of the limit here, leaving 3 spare.
	//
	// With this rate limt implementation, the behavior should be that ~7 new accounts
	// should be serviced at every renewal interval.
	// For a server with 100 accounts, it should take 14 intervals = 7 days.
	if data.AccountKey == "" {
		if acmeRegistrationsLimit == nil {
			acmeRegistrationsLimit = ratelimit.NewBucket(3*time.Hour, int64(config.AutoSSLACMERegistrationsLimit))
		}

		if _, avail := acmeRegistrationsLimit.TakeMaxDuration(1, time.Minute); !avail {
			time.Sleep(5 * time.Second)
			return nil, nil, fmt.Errorf("Skipping AutoSSL for user because server is too close to ACME Registrations rate limit")
		}
	}

	accountSummary, err := whmCl.AccountSummary(username)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to fetch account summary: %v", err)
	}

	if err := accountPreflight(username, accountSummary, cp, data); err != nil {
		if err == errNoFeature || err == errAccountSuspended {
			l.WithError(err).Println("Skipping because of pre-flight non-fatal failure")
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("Experienced fatal pre-flight error for %s: %v", username, err)
	}

	newCerts := map[string]*common.NVDataDomainCerts{}

	cryptoParams := client.GetCryptoParams()

	if data.AccountKey == "" {
		if err := common.CreateAccountKey(data, cp, cryptoParams); err != nil {
			return nil, nil, fmt.Errorf("Creating Let's Encrypt account private key - %v", err)
		}
	}

	l.Info("AutoSSL running")

	accessible, preflightDebug, err := gatherAccessibleDomains(username, cp, names)
	if err != nil {
		return nil, preflightDebug, fmt.Errorf("Failed to get accessible autossl domains for %s: %v", username, err)
	}

	if len(accessible) == 0 {
		if retryIfFail {
			l.Info("Enqueuing for AutoSSL deferred retry")
			if err := enqueueAutoSSLRetry(username, names); err != nil {
				l.WithError(err).Error("Failed to enqueue for AutoSSL deferred retry")
			}
		}

		return nil, preflightDebug, nil
	}

	if retryIfFail {
		if err := dequeueAutoSSLRetry(username); err != nil {
			l.WithError(err).Error("Failed to dequeue AutoSSL deferred retry")
		}
	}

	grouped, _, _ := common.GroupAllDomains(accessible) // should be no error here

	if data.Certs == nil {
		data.Certs = map[string]*common.NVDataDomainCerts{}
	}

	days30 := int64((24 * time.Hour * time.Duration(config.RenewalCountdownDays)).Seconds())

	// generate "pending" stuff
	for k, v := range grouped {
		if data.IsDomainAReuseTarget(k) {
			l.WithField("root", k).Info("Skipping because domain is the target of a certificate re-use")
			continue
		}
		// Gather alt names
		alt := []string{}
		for kk := range v {
			alt = append(alt, kk)
		}

		l.WithField("Cert. Names", alt).Info("AutoSSL generating certificate")

		// RATELIMIT: "Names/Certificate", 100
		if len(alt)+1 > 100 {
			l.WithFields(log.Fields{
				"Num. Names":   len(alt) + 1,
				"Primary Name": k}).Info("Skipping because it has more than 100 names")
			continue
		}

		// use existing cert if it's more than 30 days before expiring and contains all the alt names
		existingCertData := data.Certs[k]
		if existingCertData != nil {
			existingCert, valid := certificateValid(existingCertData.DomainCert, existingCertData.IssuerCert, existingCertData.Domain)
			if valid && time.Now().Unix() < existingCert.NotAfter.Unix()-days30 && common.ArrayProperSubset(alt, existingCert.DNSNames) {
				l.Info("Using existing issued certificate")

				newCerts[k] = existingCertData
				continue
			}
		}

		toIssue := &common.NVDataDomainCerts{
			Domain:   k, // specifically include the root domain so no issues with renewal or ui problems when not keyed by root domain
			AltNames: alt,
		}

		// Re-use domain key if possible
		if existingCertData != nil && existingCertData.DomainKey != "" {
			toIssue.DomainKey = existingCertData.DomainKey
		} else {
			key, err := common.DefaultPrivateKeyFunc(cryptoParams)()
			if err != nil {
				return nil, preflightDebug, fmt.Errorf("Error generating private key for domain %s - %v", k, err)
			}
			toIssue.DomainKey = key.AsPEM()
		}

		docroot := ""
		for _, vv := range v {
			docroot = vv.DocumentRoot
			break
		}
		if docroot == "" {
			return nil, preflightDebug, fmt.Errorf("Unable to determine document root for domain %v", v)
		}

		issued, err := getRenewedCert(toIssue, data.AccountKey, username, docroot, cp, false)
		if err != nil {
			return nil, preflightDebug, fmt.Errorf("Failed to get certificate for %v: %v, aborting", v, err)
		}

		data.Certs[k] = issued
		newCerts[k] = issued

		// Save every time just avoid losing certs if error with nvdata
		if _, err := cp.SetNVData(common.NVDatastoreName, data); err != nil {
			return nil, preflightDebug, fmt.Errorf("Error setting nvdata for account %s - %v", username, err)
		}
	}

	l.Info("AutoSSL installing certificates to cPanel ...")

	// only install ones that actually changed
	for k, cert := range newCerts {
		l = l.WithField("Cert Domain", cert.Domain)
		installed, err := installCertNoRestart(cp, cert.Domain, time.Unix(cert.CertExpiry, 0), cert)
		if err != nil {
			l.WithError(err).Error("Failed to install certificate")
			continue
		}

		data.Certs[k].CertId = installed.Data.CertId
		data.Certs[k].KeyId = installed.Data.KeyId
		if _, exists := newCerts[k]; exists {
			newCerts[k] = data.Certs[k]
		}
	}

	if _, err := cp.SetNVData(common.NVDatastoreName, data); err != nil {
		return nil, preflightDebug, fmt.Errorf("Error setting nvdata for account %s - %v", username, err)
	}

	return newCerts, preflightDebug, nil

}

func removeCertificates(username string, names []string) (map[string]*common.NVDataDomainCerts, error) {
	if !lockUser(username) {
		return nil, fmt.Errorf("User %s has an open lock", username)
	}
	defer unlockUser(username)

	l := log.WithFields(log.Fields{
		"Function": removeCertificates,
		"Username": username,
		"Names":    names,
	})

	deleted := map[string]*common.NVDataDomainCerts{}

	cp, err := makeCpanelClient(username)
	if err != nil {
		return nil, fmt.Errorf("Failed to make impersonation client for %s: %v", username, err)
	}

	data, err := common.GetAndParseNVData(cp)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse nvdata for %s: %v", username, err)
	}

	for _, name := range names {
		cert, exists := data.Certs[common.NormalizeDomain(name)]
		if !exists {
			l.WithField("Skipped", name).Println("Skipping remove because it doesn't exist")
			continue
		}

		if _, err := cp.DeleteSSL(name); err != nil {
			l.WithError(err).WithField("Domain", name).Error("Failed to delete SSL")
		}

		if _, err := cp.DeleteCert(cert.CertId); err != nil {
			l.WithError(err).WithField("Domain", name).Error("Failed to delete cert")
		}

		if _, err := cp.DeleteKey(cert.KeyId); err != nil {
			l.WithError(err).WithField("Domain", name).Error("Failed to delete key")
		}

		deleted[name] = cert
		delete(data.Certs, common.NormalizeDomain(name))
	}

	if _, err := cp.SetNVData(common.NVDatastoreName, data); err != nil {
		return nil, fmt.Errorf("Failed to save nvdata for %s: %v", username, err)
	}

	return deleted, nil
}

type autoSSLDeferred struct {
	Username    string
	Names       []string
	Attempt     int
	NextAttempt int64
}

func enqueueAutoSSLRetry(username string, names []string) error {
	def := autoSSLDeferred{
		Username:    username,
		Names:       names,
		Attempt:     0,
		NextAttempt: time.Now().Add(1 * time.Minute).Unix(),
	}

	l := log.WithFields(log.Fields{
		"Function": "enqueueAutoSSLRetry",
		"Username": username,
		"Names":    names,
	})

	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("autossl_deferred"))
		if err != nil {
			return err
		}

		// if there's an existing entry, we need to increment attempts
		existingBytes := bucket.Get([]byte(username))
		if len(existingBytes) > 0 {
			var existing autoSSLDeferred
			if err := json.Unmarshal(existingBytes, &existing); err != nil {
				// in case of error, just ignore the existing v
				l.WithError(err).Error("Unmarshal existing error")
			} else {
				// increment attempts and nexttime
				def.Attempt = existing.Attempt + 1
				def.NextAttempt = time.Now().Add(time.Minute * time.Duration(math.Pow(2, float64(def.Attempt)))).Unix()

				// if we're past max, delete and bail out
				if def.Attempt > int(math.Max(3, float64(config.AutoSSLMaxRetries))) {
					l.Info("Max attempts exceeded, dequeuing")
					return bucket.Delete([]byte(username))
				}
			}
		}

		enc, err := json.Marshal(def)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(username), enc)
	})
}

func dequeueAutoSSLRetry(username string) error {
	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("autossl_deferred"))
		if err != nil {
			return err
		}
		return bucket.Delete([]byte(username))
	})
}

func processAutoSSLDeferred() {
	for {
		queued := []autoSSLDeferred{}

		// read out the deferreds
		if err := db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists([]byte("autossl_deferred"))
			if err != nil {
				return err
			}

			if err := bucket.ForEach(func(k, v []byte) error {
				var out autoSSLDeferred
				if err := json.Unmarshal(v, &out); err != nil {
					log.WithField("Bytes", string(v)).WithError(err).Error("processAutoSSLDeferred unmarshal error")
					return nil
				}

				// skip if nextattempt not elapsed yet
				if time.Unix(out.NextAttempt, 0).Before(time.Now()) {
					return nil
				}

				queued = append(queued, out)
				return nil
			}); err != nil {
				return err
			}

			return nil
		}); err != nil {
			log.Error(err)
		}

		for _, v := range queued {
			log.WithField("Queued", v).Info("Processing AutoSSL deferred")

			// if an error occurs, it will be requeued or dequeued if past max attempts
			// if successful, it will be dequeued
			if _, _, err := processAutoSSLForAccount(v.Username, v.Names, true); err != nil {
				log.WithField("Queued", v).WithError(err).Error("Failed to process AutoSSL")
				continue
			}

		}

		if len(queued) > 0 {
			restartApacheIfNecessary()
		}

		time.Sleep(1 * time.Minute)
	}
}
