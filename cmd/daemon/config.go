package daemon

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"sync"

	"fmt"

	"os"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
)

type Config struct {
	DbPath                        string   `json:"db"`
	Insecure                      bool     `json:"insecure"`
	HostCert                      bool     `json:"hostcert"`
	HostAccountKey                string   `json:"hostaccountkey"`
	HostDomain                    string   `json:"hostdomain"`
	HostDocRoot                   string   `json:"hostdocroot"`
	HostDomainKey                 string   `json:"hostdomainkey"`
	HostDomainCertPem             string   `json:"hostdomaincertpem"`
	HostExtraNames                []string `json:"hostextranames"`
	IssuerCertPem                 string   `json:"issuercertpem"`
	DisableRenewalMail            bool     `json:"disablerenewalmail"`
	DisableSuccessMail            bool     `json:"disable_success_mail"`
	EnableCustomDomains           bool     `json:"enablecustomdomains"`
	CryptoKeyType                 string   `json:"crypto_key_type"`
	CryptoRsaKeySize              int      `json:"crypto_rsa_key_size"`
	CryptoEcdsaCurve              string   `json:"crypto_ecdsa_curve"`
	AutoSSL                       bool     `json:"autossl"`
	AutoSSLMaxRetries             int      `json:"autossl_max_retries"`
	AutoSSLSkipPatterns           []string `json:"autossl_skip_patterns"`
	AutoSSLSkipProxy              bool     `json:"autossl_skip_proxy_subdomains"`
	AutoSSLACMERegistrationsLimit int      `json:"autossl_acme_registrations_limit"`
	AutoSSLReplacementCutoff      int      `json:"autossl_expiry_replacement_cutoff"`
	PerAccountDelay               *int     `json:"per_account_delay_secs"`
	DeferredRestarts              bool     `json:"deferred_restarts"`
	RenewalDaysOfWeek             []string `json:"renewal_days_of_week"`
	RenewalTimeOfDay              *[2]int  `json:"renewal_times_of_day"`
	RenewalCountdownDays          int      `json:"renewal_countdown_days"`
	HookPostRenewal               string   `json:"hook_post_renewal"`
	EmailAdminDest                string   `json:"email_admin_destination"`
	Reporting                     struct {
		Interval  string `json:"interval"` // time.ParseDuration
		Failures  bool   `json:"failures"`
		Successes bool   `json:"successes"`
		SendEmpty bool   `json:"send_empty"`
	} `json:"reporting"`
	ExternalMailServer struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Insecure    bool   `json:"insecure"`
		FromAddress string `json:"from_address"`
		Username    string `json:"username"`
		Password    string `json:"password"`
	} `json:"external_mail_server"`
	ChallengeMethods    []string  `json:"enabled_challenge_methods"`
	DNSChallengeDelay   *int      `json:"dns_challenge_delay_secs"`
	AutocheckedPrefixes *[]string `json:"ui_autochecked_prefixes"`
	PreferredIssuerCN   string    `json:"preferred_issuer_cn"`
}

var config Config
var configMu sync.Mutex

func ReadConfig() error {
	var tmpConf Config

	confBytes, err := ioutil.ReadFile(common.ConfigPath)
	if err != nil || len(confBytes) == 0 {
		return errors.New("No config file present, using default values")
	}
	if err := json.Unmarshal(confBytes, &tmpConf); err != nil {
		return fmt.Errorf("Failed to unmarshal config: %s", err.Error())
	}

	if tmpConf.DbPath == "" {
		tmpConf.DbPath = "/var/lib/letsencrypt-cpanel.db"
	}
	if tmpConf.PerAccountDelay == nil {
		delay := 15
		tmpConf.PerAccountDelay = &delay
	}

	if tmpConf.RenewalTimeOfDay != nil {
		start := tmpConf.RenewalTimeOfDay[0]
		end := tmpConf.RenewalTimeOfDay[1]

		if (start < 0 || start > 23) ||
			(end < 0 || end > 23) ||
			(end <= start) {
			return errors.New("renewal_time_of_day is invalid")
		}
	}

	if tmpConf.RenewalCountdownDays <= 0 || tmpConf.RenewalCountdownDays > 60 {
		tmpConf.RenewalCountdownDays = 32
	}

	if len(tmpConf.ChallengeMethods) == 0 {
		tmpConf.ChallengeMethods = []string{"http-01", "dns-01"}
	}

	if tmpConf.DNSChallengeDelay == nil {
		i := 5
		tmpConf.DNSChallengeDelay = &i
	}

	if tmpConf.AutoSSLACMERegistrationsLimit < 1 || tmpConf.AutoSSLACMERegistrationsLimit > 10 {
		tmpConf.AutoSSLACMERegistrationsLimit = 7
	}

	if tmpConf.AutocheckedPrefixes == nil {
		tmpConf.AutocheckedPrefixes = &([]string{"www.", "mail."})
	}

	if tmpConf.AutoSSLReplacementCutoff <= 0 || tmpConf.AutoSSLReplacementCutoff >= 90 {
		tmpConf.AutoSSLReplacementCutoff = 2
	}

	// If the Let's Encrypt ACME server is still offering the legacy cross-sign as an alternate
	// chain, then use it. Once it's no longer offered, this won't do anything.
	if tmpConf.PreferredIssuerCN == "" {
		tmpConf.PreferredIssuerCN = common.PreferredChainDST
	}

	if tmpConf.CryptoKeyType == "" {
		tmpConf.CryptoKeyType = "rsa"
	}
	if tmpConf.CryptoRsaKeySize == 0 {
		tmpConf.CryptoRsaKeySize = 2048
	}
	if tmpConf.CryptoEcdsaCurve == "" {
		tmpConf.CryptoEcdsaCurve = "p-256"
	}

	configMu.Lock()
	config = tmpConf
	configMu.Unlock()

	return nil
}

func writeConfigFile(v Config, filename string, perm os.FileMode) error {
	confBytes, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return fmt.Errorf("Unable to marshal config: %v", err)
	}
	err = ioutil.WriteFile(filename, confBytes, perm)
	if err != nil {
		return fmt.Errorf("Error writing config: %v", err)
	}
	return nil
}

func WriteConfig(v Config) error {
	return writeConfigFile(v, common.ConfigPath, common.ConfigPermissions)
}

func CopyConfig() Config {
	var out Config
	*(&out) = *(&config) // yes, it's pointless, but just to be clear
	return out
}

func GetAdminEmail() string {
	e := config.EmailAdminDest
	if e == "" {
		hn, _ := os.Hostname()
		return "root@" + hn
	}
	return e
}

// UpdateConfigExclusive performs an exclusive update on
// the daemon configuration and then saves it to the filesystem.
// It is safe to use concurrently.
func UpdateConfigExclusive(updateFn func(c *Config)) error {
	configMu.Lock()
	defer configMu.Unlock()

	tmpConf := CopyConfig()
	updateFn(&tmpConf)

	config = tmpConf
	return writeConfigFile(config, common.ConfigPath, common.ConfigPermissions)
}
