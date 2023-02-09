package daemon

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"

	log "github.com/sirupsen/logrus"

	"os/exec"

	"os"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
)

var forceRenewalCh chan struct{}

func checkHostCert(exitCh chan<- error) {
	forceRenewalCh = make(chan struct{}, 1) // buffered so we can queue 1 one force request

	// Don't run immediately, wait for things to settle
	time.Sleep(10 * time.Second)

	for {
		if !config.HostCert {
			select {
			case <-time.After(RenewalsInterval * time.Minute):
				continue
			case <-forceRenewalCh:
				log.Info("Got Hostcert settings update, skipping rest of sleep interval")
				continue
			}
		}

		log.Info("Beginning Hostcert run ...")

		// ===============================================================
		// === BEGIN INITIAL SEEDING OF HOSTCERT SETTINGS IF NECESSARY ===
		doWriteConfig := false
		confUpdates := CopyConfig()

		cryptoParams := client.GetCryptoParams()

		// check a host account key exists
		if confUpdates.HostAccountKey == "" {
			key, err := common.DefaultPrivateKey(cryptoParams)
			if err != nil {
				exitCh <- fmt.Errorf("Unable to make a key for host certificates: %v", err)
				return
			}
			confUpdates.HostAccountKey = key.AsPEM()
			doWriteConfig = true
		}

		currentHn, err := os.Hostname()
		if err != nil {
			exitCh <- fmt.Errorf("Unable to determine hostname: %v", err)
			return
		}

		// Reset the hostname if its different to os.Hostname UNLESS its reverted to ec2 *.internal
		if confUpdates.HostDomain == "" || (currentHn != confUpdates.HostDomain && !strings.HasSuffix(currentHn, ".internal")) {
			confUpdates.HostDomain = currentHn
			doWriteConfig = true
		}

		if confUpdates.HostDocRoot == "" {
			confUpdates.HostDocRoot = "/usr/local/apache/htdocs"
			doWriteConfig = true
		}

		if confUpdates.HostDomainKey == "" {
			key, err := common.DefaultPrivateKey(cryptoParams)
			if err != nil {
				exitCh <- err
				return
			}
			confUpdates.HostDomainKey = key.AsPEM()
			doWriteConfig = true
		}
		// === END INITIAL SEEDING OF HOSTCERT SETTINGS IF NECESSARY ===
		// ===============================================================

		// Because this whole process takes a while
		// we change only the fields of config that
		// we actually mutate in this function
		wc := func(c Config) error {
			if !doWriteConfig {
				return nil
			}
			return UpdateConfigExclusive(func(newConf *Config) {
				newConf.HostDomain = c.HostDomain
				newConf.HostDocRoot = c.HostDocRoot
				newConf.HostDomainKey = c.HostDomainKey
				newConf.HostAccountKey = c.HostAccountKey
				newConf.HostExtraNames = c.HostExtraNames
				newConf.HostDomainCertPem = c.HostDomainCertPem
				newConf.IssuerCertPem = c.IssuerCertPem
				newConf.Insecure = c.Insecure
				doWriteConfig = false
			})
		}

		if err := wc(confUpdates); err != nil {
			log.WithError(err).Error("Failed to write config in HostCert")
			exitCh <- err
			return
		}

		log.WithField("HostDomain", config.HostDomain).Info("Checking service certificates")

		sslcomp, err := whmCl.FetchServiceSslComponents()
		if err != nil {
			log.WithError(err).Error("Failed to fetch host service ssl components")
			log.Info("Scheduling next check hostcert in 1 minute")

			time.Sleep(1 * time.Minute)
			continue
		}

		days30 := int64((24 * time.Hour * time.Duration(config.RenewalCountdownDays)).Seconds())

		// We track revocation status here so we don't end up repeating the same OCSP query multiple
		// times for every WHM service.
		// Map is leaf PEM -> isRevoked
		revocationStatuses := map[string]bool{}

		for _, srvc := range sslcomp.Data.Services {
			// Skip, apple-managed
			if strings.HasSuffix(srvc.Service, "_apns") {
				continue
			}

			_, valid := certificateValid(srvc.Certificate, srvc.CABundle, confUpdates.HostDomain)

			l := log.WithFields(log.Fields{
				"Service":       srvc.Service,
				"Domain":        confUpdates.HostDomain,
				"Extra Names":   confUpdates.HostExtraNames,
				"Document Root": confUpdates.HostDocRoot,
			})

			if _, exists := revocationStatuses[srvc.Certificate]; !exists {
				revoked, err := isCertificateRevokedOCSP(srvc.Certificate, srvc.CABundle)
				if err != nil {
					l.WithError(err).Warn("Failed to check revocation status, assuming not revoked")
				}
				revocationStatuses[srvc.Certificate] = revoked
			}

			if revocationStatuses[srvc.Certificate] {
				l = l.WithField("revoked", true)
				// In the case of revocation, delete whatever existing certificate we have stored in configuration
				// so that it cannot be re-used next time.
				confUpdates.IssuerCertPem = ""
				confUpdates.HostDomainCertPem = ""

				pk, _ := common.DefaultPrivateKey(cryptoParams)
				confUpdates.HostDomainKey = pk.AsPEM()
				doWriteConfig = true
			}

			// if installed cert is valid, not self-signed and have more than 30 days left, and have all the host extra names in the certificate (cert may have more, but must contain at least all of the extra names)
			// then skip
			if valid &&
				int64(srvc.CertificateInfo.IsSelfSigned) != 1 &&
				time.Now().Unix() < int64(srvc.CertificateInfo.NotAfter)-days30 &&
				common.ArrayProperSubset(confUpdates.HostExtraNames, srvc.CertificateInfo.Domains) &&
				!revocationStatuses[srvc.Certificate] {
				l.Debugf("Certificate is valid, not self signed and has more than %d days left - not issuing new", config.RenewalCountdownDays)
				continue
			}

			// otherwise we need to install a new certificate
			cert := ""
			issuer := ""

			// if we already have a valid cert in config, use it
			configCert, valid := certificateValid(confUpdates.HostDomainCertPem, confUpdates.IssuerCertPem, confUpdates.HostDomain)
			if valid && time.Now().Unix() < configCert.NotAfter.Unix()-days30 && common.ArrayProperSubset(confUpdates.HostExtraNames, configCert.DNSNames) {
				l.Info("Using existing host certificate for service")

				cert = confUpdates.HostDomainCertPem
				issuer = confUpdates.IssuerCertPem
			} else {
				// otherwise fetch a new one
				l.Info("Fetching new certificate for service")

				// if extra names are configured, issue them
				names := append([]string{confUpdates.HostDomain}, confUpdates.HostExtraNames...)

				docroot := []string{}
				if _, err := os.Stat("/var/www/html"); err == nil && strings.TrimSuffix(confUpdates.HostDocRoot, "/") != "/var/www/html" {
					docroot = append(docroot, "/var/www/html")
				}
				if _, err := os.Stat("/usr/local/apcahe/htdocs"); err == nil && strings.TrimSuffix(confUpdates.HostDocRoot, "/") != "/usr/local/apache/htdocs" {
					docroot = append(docroot, "/usr/local/apache/htdocs")
				}
				docroot = append(docroot, confUpdates.HostDocRoot)

				// fine to use default create file as it's all controlled by root anyway
				nvcert, err := common.RequestCert(common.CertificateRequest{
					AccountKeyPEM:   confUpdates.HostAccountKey,
					Domains:         names,
					DocRoots:        docroot,
					Method:          "http-01",
					CpanelAPI:       cpanel.CpanelApi{},
					PKF:             common.PrivateKeyFromPem(confUpdates.HostDomainKey),
					PreferredIssuer: confUpdates.PreferredIssuerCN,
				})
				if err != nil {
					l.WithError(err).Error("Failed to request service certificate")
					SendMail(GetAdminEmail(),
						"[Let's Encrypt SSL] Failed to request service certificate",
						"An error was encountered requesting certificate for host domain {{.Domain}}:\n\n  {{.Error}}\n\nService certificate was not renewed.",
						"",
						MailArgs{
							"Domain": strings.Join(names, ","),
							"Error":  err,
						}, confUpdates.Insecure)
					break
				}

				cert = nvcert.DomainCert
				issuer = nvcert.IssuerCert

				confUpdates.HostDomainCertPem = nvcert.DomainCert
				confUpdates.IssuerCertPem = nvcert.IssuerCert

				doWriteConfig = true
			}

			// Write first time to persist new keys and certs
			// before we try to install service certs
			// this way we avoid re-issuing on new attempts
			_ = wc(confUpdates)

			// install certificate to all services
			err = installCertificates(sslcomp.Services(), cert, confUpdates.HostDomainKey, issuer)
			if err != nil {
				l.WithError(err).Error("Failed to install new service certificate")
				SendMail(GetAdminEmail(),
					"[Let's Encrypt SSL] Failed to install new host service certificate",
					"An error was encountered installing host certificate for host domain {{.Domain}}:\n\n  {{.Error}}\n\nService certificate was not renewed.",
					"",
					MailArgs{
						"Domain": confUpdates.HostDomain,
						"Error":  err,
					}, confUpdates.Insecure)
				break
			}

			l.Info("Installed new service certificate, restarting cpsrvd")
			_, err = whmCl.RestartService("cpsrvd")
			if err != nil {
				err = exec.Command("/scripts/restartsrv_cpsrvd").Run()
				if err != nil {
					l.WithError(err).Error("Failed to restart cpsrvd")
					SendMail(GetAdminEmail(),
						"[Let's Encrypt SSL] Failed to restart cpsrvd",
						"A new service certificate was installed for {{.Domain}}, however cpsrvd failed to restart. Please restart cpsrvd manually to use this new certificate.",
						"",
						MailArgs{
							"Domain": confUpdates.HostDomain,
						}, confUpdates.Insecure)
				}
			}

			if confUpdates.Insecure {
				// it's not totally critical to restart the process at this point
				// probably attracts more risk than necessary to do it automatically
				// DOCUMENT the fact that the daemon should be restarted when transitioning
				// from insecure to secure
				l.Info("Please restart your letsencrypt-cpanel daemon")
				SendMail(GetAdminEmail(),
					"[Let's Encrypt SSL] Please restart your letsencrypt-cpanel daemon",
					"A new service certificate was installed for {{.Domain}} and the letsencrypt-cpanel daemon was previously running in insecure mode and has now been switched to secure. We recommend restarting the letsencrypt-cpanel daemon to use the new secure setting.",
					"",
					MailArgs{"Domain": confUpdates.HostDomain}, confUpdates.Insecure)
				confUpdates.Insecure = false
				doWriteConfig = true
			}

			// write second time to persist 'Insecure' setting
			wc(confUpdates)

			l.Info("Installed host service certificate")

			// restart rpc since we got a new certificate
			if rpcRestartCh != nil {
				select {
				case rpcRestartCh <- struct{}{}:
					l.Info("Delivered rpc restart message")
				case <-time.After(1 * time.Second):
					l.Warn("Could not deliver rpc restart check")
				}
			}

			SendMail(GetAdminEmail(),
				"[Let's Encrypt SSL] Installed host service certificate",
				"A new service certificate was installed for {{.Domain}}.",
				"",
				MailArgs{"Domain": confUpdates.HostDomain}, confUpdates.Insecure)

			// only need to install the certificate once, as it's installed to all services
			break
		}

		revocationStatuses = nil

		select {
		case <-time.After(RenewalsInterval * time.Hour):
			continue
		case <-forceRenewalCh:
			log.Info("Got Hostcert settings update, skipping rest of sleep interval")
			continue
		}
	}
}

func certificateValid(certPem, issuerPem, hostname string) (*x509.Certificate, bool) {
	l := log.WithFields(log.Fields{
		"Function": "certificateValid",
		"Hostname": hostname,
	})
	if certPem == "" {
		l.Info("CHECK: NO CERT")
		return nil, false
	}

	if issuerPem == "" {
		l.Info("CHECK: NO ISSUER")
		return nil, false
	}

	if hostname == "" {
		l.Info("CHECK: NO HOSTNAME")
		return nil, false
	}

	cert, err := common.DecodeToCert(certPem)
	if err != nil {
		log.WithError(err).Info("CHECK: DECODE")
		return nil, false
	}

	interm := x509.NewCertPool()
	interm.AppendCertsFromPEM([]byte(issuerPem))

	_, err = cert.Verify(x509.VerifyOptions{DNSName: hostname, Intermediates: interm})
	if err != nil {
		l.WithError(err).Info("CHECK: VERIFY")
		return nil, false
	}

	return cert, true
}

func installCertificates(services []string, cert, key, issuer string) error {
	for _, s := range services {
		// Skip, apple-managed
		if strings.HasSuffix(s, "_apns") {
			continue
		}
		_, err := whmCl.InstallServiceSslCertificate(s, cert, key, issuer)
		if err != nil {
			return err
		}

		// 2022-03: apparently the ftpd does not get restarted automatically if its
		// service certificate is updated. so we call it here.
		if s == "ftp" {
			if _, err := whmCl.RestartService("ftpd"); err != nil {
				log.WithError(err).Error("Failed to restart ftpd after service certificate update")
			}
		}
	}
	return nil
}

func tryForceHostCertCheck() error {
	select {
	case forceRenewalCh <- struct{}{}:
	case <-time.After(1 * time.Second):
		log.Warn("Could not deliver host cert force check")
	}

	return nil
}
