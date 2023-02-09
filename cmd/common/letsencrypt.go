package common

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/domainr/dnsr"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"

	log "github.com/sirupsen/logrus"

	"io/ioutil"

	"strings"

	"crypto"
	"reflect"

	"github.com/eggsampler/acme/v3"
)

var (
	acmeHTTPClient     *http.Client
	acmeHTTPClientInit sync.Once
)

// this function is used to create a file, limit exploits from simply running os calls as root
type CreateFileFunc func(path, dir, contents string) error

// cgi runs as local user, ok to use os calls (no root symlink exploits) - don't use this as root
func DefaultCreateFile(path, dir, contents string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("Unable to create directory (%s) in your web directory: %s", dir, err)
	}
	if err := ioutil.WriteFile(path, []byte(contents), 0644); err != nil {
		return fmt.Errorf("Unable to create file (%s) in your web directory: %s", path, err)
	}
	return nil
}

type CertificateRequest struct {
	AccountKeyPEM        string
	Domains              []string
	DocRoots             []string
	Method               string
	DropPrivilegesToUser string
	CpanelAPI            cpanel.CpanelApi
	PKF                  PrivateKeyFunc
	PreferredIssuer      string
	DryRun               bool
}

func RequestCert(certReq CertificateRequest) (*NVDataDomainCerts, error) {
	// domains[0] == primary domain, anything else is an alias/parked domain

	acmeDirectory := BoulderUrl
	// For a dry-run, we are talking to the Let's Encrypt staging server.
	if certReq.DryRun {
		acmeDirectory = BoulderStagingUrl
	}

	cli, err := NewAcmeClient(acmeDirectory)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to service: %v", err)
	}

	cli.PollTimeout = 90 * time.Second

	akFunc, err := PrivateKeyFromPem(certReq.AccountKeyPEM)()
	if err != nil {
		return nil, fmt.Errorf("Error parsing account key: %v", err)
	}

	var zoneList cpanel.FetchZonesApiResponse
	if certReq.Method == "dns-01" {
		zoneList, err = certReq.CpanelAPI.FetchZones()
		if err != nil {
			return nil, fmt.Errorf("Failed to fetch zone list as required for dns-01 mode: %v", err)
		}
	}

	unwrapped := akFunc.Unwrapped()
	key, ok := unwrapped.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("Error unwrapping private key: expected crypto.Signer, got: %v", reflect.TypeOf(unwrapped))
	}
	account, err := cli.NewAccount(key, false, true)
	if err != nil {
		return nil, fmt.Errorf("Error registering account key: %v", err)
	}

	// before we create the order, we need to remove any names that are overlapped by other
	// names (such as wildcards)
	filteredDomains := StripWildcardOverlaps(certReq.Domains)

	// create new order
	var identifiers []acme.Identifier
	for _, d := range filteredDomains {
		identifiers = append(identifiers, acme.Identifier{Type: "dns", Value: d})
	}
	order, err := cli.NewOrder(account, identifiers)
	if err != nil {
		return nil, fmt.Errorf("Error creating new order: %v", err)
	}

	hasDNSChal := false
	type chalEntry struct {
		Auth acme.Authorization
		Chal acme.Challenge
	}
	var chalList []chalEntry

	// Tracks how many DNS lines we have added/modified so far
	existingLineCount := map[string]int{}

	// We are tracking the very last DNS update, if any,
	// so that we can do an interative lookup on it at the end
	// and guarantee that all changed records are being advertised
	var lastDNSName string
	var lastDNSValue string

	// If this is a dry-run, we want to deactivate each authz upon completion
	// of this function (whether or not the order is successful)
	if certReq.DryRun {
		defer func(cli acme.Client, account acme.Account, authzURLs []string) {
			log.Infof("Deactivating up to %d authzs after dry-run", len(authzURLs))
			for _, authzURL := range authzURLs {
				authz, err := cli.FetchAuthorization(account, authzURL)
				if err != nil {
					log.WithError(err).Warn("Failed to fetch authz when deactivating")
					continue
				}
				// We only need to deactivate valid authzs
				if authz.Status != "valid" {
					continue
				}
				if authz, err = cli.DeactivateAuthorization(account, authzURL); err != nil {
					log.WithError(err).WithField("authz", authzURL).Warn("Failed to deactivate authz")
					continue
				}
				log.WithField("authz", authzURL).WithField("status", authz.Status).Info("Deactivated authz")
			}
		}(cli, account, order.Authorizations)
	}

	for _, authzURL := range order.Authorizations {
		currentAuth, err := cli.FetchAuthorization(account, authzURL)
		if err != nil {
			return nil, fmt.Errorf("Error fetching order authorization: %v", err)
		}

		switch currentAuth.Status {
		case "valid":
			// no need to do this auth
			continue
		case "invalid":
			return nil, fmt.Errorf("Auth %s is invalid!", currentAuth.Identifier.Value)
		}

		currentChal, ok := currentAuth.ChallengeMap[certReq.Method]
		if !ok {
			return nil, fmt.Errorf("Challenge type %s not supported by authorization: %v",
				certReq.Method, currentAuth.ChallengeTypes)
		}

		switch currentChal.Status {
		case "valid":
			// no need to do this challenge
			continue
		case "invalid":
			return nil, fmt.Errorf("Challenge for auth %s is invalid!", currentAuth.Identifier.Value)
		}

		chalList = append(chalList, chalEntry{currentAuth, currentChal})

		if currentChal.Type == "dns-01" && !hasDNSChal {
			hasDNSChal = true
		}

		switch currentChal.Type {
		case "http-01":
			cff := DefaultCreateFile
			if certReq.DropPrivilegesToUser != "" {
				cff = func(path, dir, contents string) error {
					return ForkCreateFileUnprivileged(certReq.DropPrivilegesToUser, filepath.Base(path), contents, dir)
				}
			}

			for _, docroot := range certReq.DocRoots {
				start := time.Now()

				destPath := filepath.Join(docroot, ".well-known", "acme-challenge", currentChal.Token)
				dir, _ := filepath.Split(destPath)

				// use the given function to create the file
				if err := cff(destPath, dir, currentChal.KeyAuthorization); err != nil {
					return nil, err
				}

				log.WithFields(log.Fields{
					"authz":       authzURL,
					"destination": destPath,
					"elapsed":     time.Now().Sub(start),
				}).Info("Created http-01 validation file")

				defer os.Remove(destPath)
			}

		case "dns-01":
			txt := acme.EncodeDNS01KeyAuthorization(currentChal.KeyAuthorization)

			zoneToEdit := zoneList.FindRootForName(currentAuth.Identifier.Value)
			if zoneToEdit == "" {
				return nil, fmt.Errorf("Couldn't figure out which DNS zone to modify for dns-01 challenge for %s", currentAuth.Identifier.Value)
			}

			start := time.Now()

			zone, err := certReq.CpanelAPI.FetchZone(zoneToEdit, "TXT")
			if err != nil {
				log.WithError(err).Error("Couldn't fetch zone")
				return nil, errors.New("Failed to find the DNS zone in cPanel")
			}

			fullAcmeFqdn := "_acme-challenge." + currentAuth.Identifier.Value + "."

			exists, existing := zone.Find(fullAcmeFqdn, "TXT")

			nLinesAvailable := len(existing)
			nLinesUsed := existingLineCount[fullAcmeFqdn]

			log.WithFields(log.Fields{
				"lines_available": nLinesAvailable,
				"lines_used":      nLinesUsed,
				"fqdn":            fullAcmeFqdn,
				"existing":        existing,
			}).Info("Counted up the lines")

			if exists && nLinesAvailable > nLinesUsed {
				log.WithFields(log.Fields{
					"line_to_use": existing[nLinesUsed],
					"txt":         txt,
				}).Info("Found a line to update")
				if err := certReq.CpanelAPI.EditZoneTextRecord(existing[existingLineCount[fullAcmeFqdn]], zoneToEdit, txt, "1"); err != nil {
					log.WithError(err).Error("Failed to modify txt record")
					return nil, errors.New("Could not modify TXT record")
				}
			} else {
				if err := certReq.CpanelAPI.AddZoneTextRecord(zoneToEdit, fullAcmeFqdn, txt, "1"); err != nil {
					log.WithError(err).Error("Failed to add txt record")
					return nil, errors.New("Could not add TXT record")
				}
			}
			// Increment the lines used count for both adding and modifying lines,
			// as the next iteration needs to know how many we are using
			existingLineCount[fullAcmeFqdn] = nLinesUsed + 1

			log.WithFields(log.Fields{
				"authz":   authzURL,
				"name":    fullAcmeFqdn,
				"elapsed": time.Now().Sub(start),
				"value":   txt,
			}).Info("Created dns-01 validation record")

			lastDNSName = fullAcmeFqdn
			lastDNSValue = txt

		default:
			// shouldnt happen, we only select a challenge with a method we want
			return nil, fmt.Errorf("Unsupported challenge type: %s", certReq.Method)
		}
	}

	if hasDNSChal {
		delay, _ := client.GetDNSChallengeDelay()
		log.Infof("Sleeping %d seconds to allow DNS cluster to catch up ...", delay)
		time.Sleep(time.Duration(delay) * time.Second)

		// Up to 3 times, try to make an iterative lookup to check that the DNS record
		// is being advertised by the authoritative nameservers
		//
		// If the check eventually fails, that's fine, but we need to make sure we don't
		// update the challenge too early if it was going to succeed
		start := time.Now()
		for i := 0; i < 3; i++ {
			rrs := dnsr.NewWithTimeout(0, 5*time.Second).Resolve(lastDNSName, "TXT")
			for _, rr := range rrs {
				if rr.Value == lastDNSValue {
					log.
						WithField("duration", time.Since(start)).
						WithField("rr", rr).
						Info("Verified that DNS records are being advertised")
					goto end
				}
			}
			time.Sleep(time.Duration(delay) * time.Second)
		}
		log.WithField("duration", time.Since(start)).Info("Unable to verify that DNS records are being advertised")
	end:
	}

	for _, chal := range chalList {
		if _, err := cli.UpdateChallenge(account, chal.Chal); err != nil {
			return nil, fmt.Errorf("Updating challenge for %s: %v (order URL: %v)", chal.Auth.Identifier.Value, err, order.URL)
		}
	}

	// use the given function to get a domain key
	domainKey, err := certReq.PKF()
	if err != nil {
		return nil, fmt.Errorf("Error getting domain key: %v", err)
	}

	csr, err := newCSR(filteredDomains, domainKey)
	if err != nil {
		return nil, fmt.Errorf("Error during generation of CSR: %v", err)
	}

	order, err = cli.FinalizeOrder(account, order, csr)
	if err != nil {
		return nil, fmt.Errorf("Error finalizing order: %v", err)
	}

	allChains, err := cli.FetchAllCertificates(account, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("Error fetching order certificates: %w", err)
	}

	chain, err := chooseBestChain(certReq.PreferredIssuer, allChains, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("Error selecting certificate: %w", err)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("No certificates returned")
	}
	if len(chain) == 1 {
		return nil, fmt.Errorf("No issuer certificate was included")
	}

	retCert := &NVDataDomainCerts{
		Domain:          certReq.Domains[0],
		OrderUrl:        order.URL,
		DomainKey:       domainKey.AsPEM(),
		ChallengeMethod: certReq.Method,
	}
	if len(certReq.Domains) > 1 {
		retCert.AltNames = certReq.Domains[1:]
	}

	retCert.DomainCert = EncodeToPEM("CERTIFICATE", chain[0].Raw)
	retCert.CertExpiry = chain[0].NotAfter.Unix()

	var s []string
	for i := 1; i < len(chain); i++ {
		s = append(s, strings.TrimSpace(EncodeToPEM("CERTIFICATE", chain[i].Raw)))
	}
	retCert.IssuerCert = strings.Join(s, "\n")

	// Fill in alternate chains from the server
	retCert.AlternateChains = make(map[string]string)
	for _, altChain := range allChains {
		if len(altChain) < 2 { // EE+1 issuer. Remember altChain includes the EE cert.
			continue
		}
		chainIssuer := altChain[len(altChain)-1].Issuer.CommonName
		retCert.AlternateChains[chainIssuer] = strings.Join(CertificateSliceToPEMSlice(altChain[1:]), "\n")
	}

	return retCert, nil
}

func chooseBestChain(preferredIssuerCN string, chains map[string][]*x509.Certificate,
	defaultCertificateURL string) ([]*x509.Certificate, error) {

	// Find any certificate where the topmost certificate has an issuer matching preferredIssuerCN
	if preferredIssuerCN != "" {
		for _, chain := range chains {
			if len(chain) == 0 {
				continue
			}
			topCert := chain[len(chain)-1]
			if topCert.Issuer.CommonName == preferredIssuerCN {
				return chain, nil
			}
		}
	}

	// Fallback: use the original URL
	if chain, ok := chains[defaultCertificateURL]; ok {
		return chain, nil
	}

	// Something went seriously wrong in the fallback, pick any chain
	// (this will be random due to random map ordering)
	log.
		WithFields(log.Fields{"default_chain_url": defaultCertificateURL}).
		Warn("In chooseBestChain, the default certificate URL was not available")
	for _, v := range chains {
		return v, nil
	}

	return nil, fmt.Errorf("there were no certificate chains to choose from")
}

func NewAcmeClient(directory string) (acme.Client, error) {
	acmeHTTPClientInit.Do(func() {
		dc := &net.Dialer{
			DualStack: false,
		}
		acmeHTTPClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, net, addr string) (net.Conn, error) {
					// Always dial IPv4 for the acme client
					return dc.DialContext(ctx, "tcp4", addr)
				},
			},
			Timeout: 60 * time.Second,
		}
	})
	return acme.NewClient(directory,
		acme.WithUserAgentSuffix("fleetssl-cpanel/"+AppVersion),
		acme.WithHTTPClient(acmeHTTPClient))
}
