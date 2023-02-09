package common

import (
	"crypto/x509"
	"fmt"
	"strings"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"

	"encoding/json"

	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

const NVDatastoreName = "letsencrypt-cpanel"

type NVDataDomainCerts struct {
	Domain          string            `json:"domain"`
	OrderUrl        string            `json:"url"`
	DomainKey       string            `json:"key"`
	DomainCert      string            `json:"cert"`
	IssuerCert      string            `json:"issuer"`
	KeyId           string            `json:"key_id"`  // the cpanel key_id from install_ssl
	CertId          string            `json:"cert_id"` // the cpanel cert_id from install_ssl
	CertExpiry      int64             `json:"cert_expiry"`
	AltNames        []string          `json:"alt_names"`
	ChallengeMethod string            `json:"challenge_method"`
	AlternateChains map[string]string `json:"alternate_chains"` // map of top_issuer -> pem (\n joined)
	PreferredIssuer string            `json:"preferred_issuer"`
}

type NVDataAccount struct {
	AccountKey       string                        `json:"accountkey"`
	LastRenewalCheck int64                         `json:"last_renewal_check"`
	Certs            map[string]*NVDataDomainCerts `json:"certs"`
	DisableMail      bool                          `json:"disable_mail"`
	Reuses           map[string]string             `json:"cert_reuses"`
}

func (a *NVDataAccount) AllNames() []string {
	out := []string{}
	for _, v := range a.Certs {
		out = append(out, append(v.AltNames, v.Domain)...)
	}
	return out
}

func (a *NVDataAccount) ContainsCertId(certId string) bool {
	for _, cert := range a.Certs {
		if cert.CertId == certId {
			return true
		}
	}
	return false
}

func (a *NVDataAccount) MapReuse(target, source string) {
	if a.Reuses == nil {
		a.Reuses = map[string]string{}
	}
	a.Reuses[target] = source
	delete(a.Certs, target)
}

func (a *NVDataAccount) ClearReuse(target string) {
	if a.Reuses == nil {
		return
	}
	delete(a.Reuses, target)
}

func (a *NVDataAccount) IsDomainAReuseTarget(target string) bool {
	if a.Reuses == nil {
		return false
	}
	return a.Reuses[target] != ""
}

func (a *NVDataAccount) GetReuseTargetsForSource(sourceMatch string) []string {
	if a.Reuses == nil {
		return nil
	}
	targets := []string{}
	for target, source := range a.Reuses {
		if sourceMatch == source {
			targets = append(targets, target)
		}
	}
	return targets
}

func (c *NVDataDomainCerts) EnsureAlternateChains() {
	// If there's anything in the alternate chains map, then we don't need to
	// backfill it.
	if len(c.AlternateChains) > 0 {
		return
	}

	c.AlternateChains = make(map[string]string)

	// If there's no issuer, there's nothing to be done.
	if c.IssuerCert == "" {
		return
	}

	// Unmarshal the PEMs into a certificate list
	certs, _ := PEMToCertificateSlice(c.IssuerCert)

	// First, create an entry for the chain as-is.
	topCert := certs[len(certs)-1]
	c.AlternateChains[topCert.Issuer.CommonName] = strings.Join(CertificateSliceToPEMSlice(certs), "\n")

	// Second, create an entry for the chain minus the top certificate, but only
	// if there are at least two certs in the list.
	if len(certs) >= 2 {
		altChain := append([]*x509.Certificate{}, certs[:len(certs)-1]...)
		altTopCert := altChain[len(altChain)-1]
		c.AlternateChains[altTopCert.Issuer.CommonName] = strings.Join(CertificateSliceToPEMSlice(altChain), "\n")
	}
}

func (c *NVDataDomainCerts) BestIssuer(preferredIssuer string) string {
	if len(c.AlternateChains) == 0 {
		return c.IssuerCert
	}

	chain, exists := c.AlternateChains[preferredIssuer]
	if exists {
		return chain
	}

	return c.IssuerCert
}

func ParseNVData(out cpanel.NVDataGetApiResult) (*NVDataAccount, error) {
	var acct NVDataAccount
	if len(out.Data) == 0 {
		return &acct, nil
	}
	if len(out.Data[0].FileContents) == 0 {
		return &acct, nil
	}
	if err := json.Unmarshal([]byte(out.Data[0].FileContents), &acct); err != nil {
		return nil, err
	}
	for _, nvcert := range acct.Certs {
		nvcert.EnsureAlternateChains()
	}
	return &acct, nil
}

// Generate a new 4096-bit RSA key to be used as the Account Key in Let's Encrypt
// Additionally, store this key in the user's nvdata store
func CreateAccountKey(account *NVDataAccount, cl cpanel.CpanelApi, params client.CryptoParams) error {
	key, err := DefaultPrivateKey(params)
	if err != nil {
		return fmt.Errorf("Error generating account key: %v", err)
	}

	account.AccountKey = key.AsPEM()

	if account.Certs == nil {
		account.Certs = make(map[string]*NVDataDomainCerts)
	}

	_, err = cl.SetNVData(NVDatastoreName, account)
	if err != nil {
		return fmt.Errorf("Error storing the account key: %v", err)
	}

	return nil
}

func GetAndParseNVData(cp cpanel.CpanelApi) (*NVDataAccount, error) {
	// Gather up data from the cPanel account required to issue the certificate
	// NVData
	rawNVData, err := cp.GetNVData(NVDatastoreName)
	if err != nil {
		return nil, err
	}
	return ParseNVData(rawNVData)
}
