package common

import (
	"fmt"
	"os/exec"
	"strings"

	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
	"github.com/domainr/dnsr"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"

	log "github.com/sirupsen/logrus"
)

type DomainEntry struct {
	Domain       string
	DomainRoot   string
	DomainType   string
	DocumentRoot string
	User         string
}

type DomainList map[string]DomainEntry

func (dl DomainList) AddDomainEntry(entry DomainEntry) {
	if _, present := dl[entry.Domain]; !present {
		dl[entry.Domain] = entry
	}
}

func (dl DomainList) AddDomain(domain, dtype, docroot, user, domainroot string) {
	dl.AddDomainEntry(DomainEntry{
		Domain:       domain,
		DomainType:   dtype,
		DocumentRoot: docroot,
		User:         user,
		DomainRoot:   domainroot,
	})
}

func (dl DomainList) AddDomains(domains []string, dtype, docroot, user, domainroot string) {
	for _, domain := range domains {
		if len(domain) > 0 {
			dl.AddDomain(domain, dtype, docroot, user, domainroot)
		}
	}
}

func (dl DomainList) RemoveDomain(domain string) {
	delete(dl, domain)
}

func (dl DomainList) FindUser(docroot string) string {
	for _, d := range dl {
		if d.DocumentRoot == docroot {
			return d.User
		}
	}
	return ""
}

func (dl DomainList) GatherNames() []string {
	out := []string{}
	for _, v := range dl {
		out = append(out, v.Domain)
	}
	return out
}

func CreateDomainList(domainResponse cpanel.DomainsDataApiResponse, parkedResponse cpanel.ListParkedDomainsApiResponse) DomainList {
	domains := DomainList{}

	// main
	domains.AddDomain(domainResponse.Data.MainDomain.Domain, "Main", domainResponse.Data.MainDomain.DocumentRoot, domainResponse.Data.MainDomain.User, domainResponse.Data.MainDomain.Domain)
	// addon
	for _, addon := range domainResponse.Data.AddonDomains {
		domains.AddDomain(addon.Domain, "Addon", addon.DocumentRoot, addon.User, addon.Domain)
		domains.AddDomain(addon.ServerName, "Addon Alias", addon.DocumentRoot, addon.User, addon.Domain)
	}
	// sub
	for _, sub := range domainResponse.Data.Subdomains {
		domains.AddDomain(sub.Domain, "Sub", sub.DocumentRoot, sub.User, sub.Domain)
	}
	// alias
	for _, parked := range domainResponse.Data.ParkedDomains {
		domains.AddDomain(parked, "Alias", domainResponse.Data.MainDomain.DocumentRoot,
			domainResponse.Data.MainDomain.User, domainResponse.Data.MainDomain.Domain)
	}
	/*	for _, parked := range parkedResponse.Data {
		user := domains.FindUser(parked.Dir)
		if user != "" {
			domains.AddDomain(parked.Domain, "Parked", parked.Dir, user, parked.Domain)
		}
	}*/

	// aliases that arent parked domainsdomains
	// alias for maindomain
	domains.AddDomains(strings.Split(domainResponse.Data.MainDomain.ServerAlias, " "), "Alias", domainResponse.Data.MainDomain.DocumentRoot, domainResponse.Data.MainDomain.User, domainResponse.Data.MainDomain.Domain)
	// alias for addondomain
	for _, addon := range domainResponse.Data.AddonDomains {
		domains.AddDomains(strings.Split(addon.ServerAlias, " "), "Addon Alias", addon.DocumentRoot, addon.User, addon.Domain)
	}
	// alias for subdomain
	for _, sub := range domainResponse.Data.Subdomains {
		domains.AddDomains(strings.Split(sub.ServerAlias, " "), "Sub Alias", sub.DocumentRoot, sub.User, sub.Domain)
	}

	// don't remove redirected aliases, people can use these as long as they use a rewritecond rule (or similar)
	/* for _, parked := range parkedResponse.Data {
		// only if not redirected
		if parked.Status != cpanel.ParkedStatusNotRedirected {
			domains.RemoveDomain(parked.Domain)
			domains.RemoveDomain("www." + parked.Domain) // workaround, this api call doesn't include www. entries
		}
	}*/

	return domains
}

func GroupDomains(wantedDomains []string, allDomains DomainList, limitToVhost string) (map[string]DomainList, []string, error) {
	grouped := map[string]DomainList{}
	var leftovers []string

	for _, domain := range wantedDomains {
		key := domain

		// check that this is a valid domain
		entry, validDomain := allDomains[key]

		// If we encounter a virtualhost mismatch when the name is a wildcard, then we can try to identify
		// the correct virtualhost by looking at the non-wildcard version of the domain.
		if validDomain && limitToVhost != "" && entry.DomainRoot != limitToVhost && strings.HasPrefix(key, "*.") {
			key = key[2:]
			entry, validDomain = allDomains[key]
		}

		// If it's a wildcard and isn't present in allDomains, strip the wildcard prefix
		if !validDomain && strings.HasPrefix(key, "*.") {
			key = key[2:]
			entry, validDomain = allDomains[key]
		}

		// If the domain can't be found in any virtual host, then we're just going to
		// ignore it and return whatever groups can be found.
		// This way, one ungroupable domain doesn't cause renewals for an entire account
		// to have its renewals fail.
		if !validDomain || (limitToVhost != "" && entry.DomainRoot != limitToVhost) {
			log.
				WithField("domain", domain).
				WithField("limitToVhost", limitToVhost).
				Warn("Invalid domain specified")
			leftovers = append(leftovers, key)
			continue
		}

		// add it to the grouped list
		list, present := grouped[entry.DomainRoot]
		if !present {
			list = DomainList{}
			grouped[entry.DomainRoot] = list
		}
		// Write the original wanted domain back into the entry, since if this
		// was a wildcard, we need to re-introduce the wildcard prefix.
		entry.Domain = domain
		list.AddDomainEntry(entry)
	}

	return grouped, leftovers, nil
}

func GroupAllDomains(allDomains DomainList) (map[string]DomainList, []string, error) {
	wanted := make([]string, 0, len(allDomains))

	for k := range allDomains {
		wanted = append(wanted, k)
	}

	return GroupDomains(wanted, allDomains, "")
}

func GroupNVDataDomains(certs map[string]*NVDataDomainCerts, allDomains DomainList) (map[string]DomainList, []string, error) {
	grouped := map[string]DomainList{}
	var leftovers []string

	for root, cert := range certs {
		list, lo, err := GroupDomains(append(cert.AltNames, cert.Domain), allDomains, root)
		if err != nil {
			return grouped, leftovers, err
		}

		if len(lo) > 0 {
			leftovers = append(leftovers, lo...)
		}

		grouped[root] = list[root]
	}

	return grouped, leftovers, nil
}

func IsDomainAccessible(username string, domain DomainEntry, cp cpanel.CpanelApi) error {
	// First we check if the domain is registered, e.g. we can
	// get any records using iterative dns from the root servers
	r := dnsr.NewWithTimeout(1000, 10*time.Second)
	rrs := r.Resolve(domain.Domain, "")
	// RRs must contain CNAME, A, or AAAA (sometimes we might get SOA/NS which is a false positive)
	resolveable := false
	for _, rr := range rrs {
		if rr.Type == "A" || rr.Type == "AAAA" || rr.Type == "CNAME" {
			resolveable = true
		}
	}
	if !resolveable {
		return fmt.Errorf("Iterative DNS lookup for %s gave no results", domain.Domain)
	}

	fn := fmt.Sprintf("plugin-test-%d", time.Now().UnixNano())
	testPath := filepath.Join(domain.DocumentRoot, ".well-known/acme-challenge")

	// 1. Create the file
	if err := ForkCreateFileUnprivileged(username, fn, fn, testPath); err != nil {
		return fmt.Errorf("Failed to create test file for %s/%s (%s): %v", username, domain.Domain, testPath, err)
	}
	defer os.Remove(filepath.Join(testPath, fn))

	// 2. Request the file
	reqUrl := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain.Domain, fn)
	if err := checkUrl(reqUrl, fn); err != nil {
		return fmt.Errorf("Failed to request url for %s (%s): %v", username, reqUrl, err)
	}

	return nil
}

func checkUrl(url, expectedContents string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := ctxhttp.Get(ctx, http.DefaultClient, url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Wanted response 200, got %d", resp.StatusCode)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if string(buf) != expectedContents {
		return errors.New("File had wrong contents")
	}

	return nil
}

// GetProxyDomainLabels is required because the way to determine
// proxy subdomains is hidden within Perl code and not exposed via APIs,
// unless the vhost is already SSL. We need to shell out to Perl.
func GetProxyDomainLabels(user string, cp cpanel.CpanelApi) ([]string, error) {
	res, err := getProxyDomainLabels0(user)
	if err == nil {
		return res, nil
	}

	vhosts, vhostsErr := cp.WebVhostsListDomains()
	if vhostsErr != nil {
		return nil, fmt.Errorf("Not able to fetch proxy subdomains in any way: perl=%v,api=%v", err, vhostsErr)
	}

	return vhosts.GetAllProxySubdomains(), nil
}

func getProxyDomainLabels0(user string) ([]string, error) {
	curExec, err := os.Executable()
	if err != nil {
		return nil, err
	}
	curExec, err = filepath.EvalSymlinks(curExec)
	if err != nil {
		return nil, err
	}

	p := filepath.Join(filepath.Dir(curExec), "get_proxy_names")
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("get_proxy_names did not exist: %v", err)
	}

	buf, err := exec.Command(p, user).CombinedOutput()
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.TrimSpace(string(buf)), "\n"), nil
}

// CleanupOldCerts will delete up to `max` unused certificates at a time
// from the cPanel account, in order to prevent unbounded growth of data.
func CleanupOldCerts(username string, cp cpanel.CpanelApi, nvdata *NVDataAccount, max int) error {
	certs, err := cp.ListSSLCerts()
	if err != nil {
		return fmt.Errorf("Failed to fetch certificates: %v", err)
	}
	// Nothing to do if there are no certificates
	if len(certs.Data) == 0 {
		return nil
	}

	l := log.WithField("user", username).WithField("function", "CleanupOldCerts")

	totalRemoved := 0
	for _, cpanelCert := range certs.Data {
		// Don't remove more than `max`
		if totalRemoved >= max {
			break
		}
		// If the cert is present in our nvdata, then we do not remove it
		if nvdata.ContainsCertId(cpanelCert.Id) {
			continue
		}
		// If the cert is not expired, then do not remove it
		if cpanelCert.Expiry().After(time.Now()) {
			continue
		}
		// If the cert is not issued by Let's Encrypt, then do not remove it
		if cpanelCert.OrgName != "Let's Encrypt" {
			continue
		}

		_, err = cp.DeleteCert(cpanelCert.Id)

		l.WithField("certId", cpanelCert.Id).
			WithField("names", cpanelCert.Domains).
			WithError(err).
			Warn("Tried to remove old certificate")
		totalRemoved++
	}

	return nil
}

// StripWildcardOverlaps filters any names that are already covered
// by another wildcard name
//
// This is required because Boulder rejects orders that contain
// overlapping domains (https://github.com/letsencrypt/boulder/pull/3542)
func StripWildcardOverlaps(names []string) []string {
	filtered := []string{}

	// Need to be able to check for existence of names
	allNames := map[string]struct{}{}
	for _, name := range names {
		allNames[name] = struct{}{}
	}

	// Collect all of the covered names that are not also
	// covered by a wildcard
	for _, name := range names {
		// Always include wildcards
		if strings.HasPrefix(name, "*.") {
			filtered = append(filtered, name)
			continue
		}

		// If the domain is already covered by our wildcards, give it a miss
		labels := strings.Split(name, ".")
		labels[0] = "*"

		if _, wildcardExists := allNames[strings.Join(labels, ".")]; wildcardExists {
			log.WithFields(log.Fields{
				"allNames": allNames,
				"name":     name,
			}).Debug("Removing name from domain list because it is already covered by a wildcard")
			continue
		}

		// Otherwise we include the name
		filtered = append(filtered, name)
	}

	return filtered
}

func MapCertificateReuse(cp cpanel.CpanelApi, data *NVDataAccount, sourceDomain, targetDomain string) error {
	sourceCert, sourceOk := data.Certs[sourceDomain]
	if !sourceOk {
		return fmt.Errorf("There is no certificate configured on the source virtual host: %s", sourceDomain)
	}

	preferredIssuerOrDefault := sourceCert.PreferredIssuer
	if preferredIssuerOrDefault == "" {
		preferredIssuerOrDefault, _ = client.GetPreferredIssuer()
	}
	issuerCert := strings.ReplaceAll(sourceCert.BestIssuer(preferredIssuerOrDefault)+"\n"+CABundle, "\n\n", "\n")

	if _, err := cp.InstallSSLKey(targetDomain, sourceCert.DomainCert, sourceCert.DomainKey, issuerCert); err != nil {
		return fmt.Errorf("Could not install the certificate to the virtual host %s: %v", targetDomain, err)
	}

	data.MapReuse(targetDomain, sourceDomain)

	if _, err := cp.SetNVData(NVDatastoreName, data); err != nil {
		return fmt.Errorf("Could not save nvdata: %v", err)
	}

	return nil
}

func UnmapCertificateReuse(cp cpanel.CpanelApi, data *NVDataAccount, targetDomain string) error {
	if !data.IsDomainAReuseTarget(targetDomain) {
		return fmt.Errorf("%s is not the target of a certificate reuse", targetDomain)
	}

	data.ClearReuse(targetDomain)

	if _, err := cp.SetNVData(NVDatastoreName, data); err != nil {
		return fmt.Errorf("Could not save nvdata: %v", err)
	}

	if _, err := cp.DeleteSSL(targetDomain); err != nil {
		return fmt.Errorf("Certificate re-use mapping was removed, but SSL uninstallation failed: %s", err.Error())
	}

	return nil
}

func GetDomainList(cp cpanel.CpanelApi) (DomainList, error) {
	domainsData, err := cp.DomainsData()
	if err != nil {
		return nil, fmt.Errorf("Fetching DomainData: %v", err)
	}
	parkedDomainsData, err := cp.ListParkedDomains()
	if err != nil {
		return nil, fmt.Errorf("Fetching ParkedDomains: %v", err)
	}
	return CreateDomainList(domainsData, parkedDomainsData), nil
}
