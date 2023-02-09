package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/cgi/cpanelcgi"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
)

type Api struct {
	pb.UnimplementedPluginServer
}

func (a Api) makeError(errs ...string) []*pb.Error {
	out := []*pb.Error{}
	for _, v := range errs {
		out = append(out, &pb.Error{Error: v})
	}
	return out
}

func (a Api) ServiceCertSetEnabled(ctx context.Context, in *pb.ServiceCertSetEnabledRequest) (*pb.ServiceCertSetEnabledResponse, error) {
	if err := UpdateConfigExclusive(func(newCfg *Config) {
		newCfg.HostCert = in.NewState
	}); err != nil {
		return &pb.ServiceCertSetEnabledResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	if in.NewState {
		if err := tryForceHostCertCheck(); err != nil {
			log.WithError(err).Warn("Couldn't force a host cert check")
		}
	}

	return &pb.ServiceCertSetEnabledResponse{}, nil
}

func (a Api) ServiceCertListDomains(ctx context.Context, in *pb.ServiceCertListDomainsRequest) (*pb.ServiceCertListDomainsResponse, error) {
	if !config.HostCert {
		return &pb.ServiceCertListDomainsResponse{
			Errors: a.makeError("Hostcert feature not enabled"),
		}, nil
	}

	list := append(config.HostExtraNames, config.HostDomain)

	return &pb.ServiceCertListDomainsResponse{
		Domains: list,
	}, nil
}

func (a Api) ServiceCertAddDomain(ctx context.Context, in *pb.ServiceCertAddDomainRequest) (*pb.ServiceCertAddDomainResponse, error) {
	var err error
	newDoms := config.HostExtraNames
	for _, s := range in.Domains {
		s = common.NormalizeDomain(s)
		if s == "" {
			continue
		}

		if s == common.NormalizeDomain(config.HostDomain) {
			return &pb.ServiceCertAddDomainResponse{
				Errors: a.makeError("Same as host domain"),
			}, nil
		}

		for _, v := range newDoms {
			if s == common.NormalizeDomain(v) {
				// already present
				continue
			}
		}

		newDoms = append(newDoms, s)
	}

	if err != nil {
		return &pb.ServiceCertAddDomainResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	if err := UpdateConfigExclusive(func(newCfg *Config) {
		newCfg.HostExtraNames = newDoms
	}); err != nil {
		return &pb.ServiceCertAddDomainResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	if err := tryForceHostCertCheck(); err != nil {
		log.WithError(err).Warn("Couldn't force a host cert check")
	}

	return &pb.ServiceCertAddDomainResponse{}, nil
}

func (a Api) ServiceCertRemoveDomain(ctx context.Context, in *pb.ServiceCertRemoveDomainRequest) (*pb.ServiceCertRemoveDomainResponse, error) {
	// Marshal the existing names as a set
	allNames := map[string]struct{}{}
	for _, existing := range config.HostExtraNames {
		allNames[common.NormalizeDomain(existing)] = struct{}{}
	}

	// Delete the requested domains from the set
	for _, toDelete := range in.Domains {
		delete(allNames, common.NormalizeDomain(toDelete))
	}

	// Marshal the set as a slice again
	newHostExtraNames := []string{}
	for domain := range allNames {
		newHostExtraNames = append(newHostExtraNames, domain)
	}

	// Update the config with the new extra names slice
	if err := UpdateConfigExclusive(func(newCfg *Config) {
		newCfg.HostExtraNames = newHostExtraNames
	}); err != nil {
		return &pb.ServiceCertRemoveDomainResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	// Re-issue the service certificate if necessary
	if err := tryForceHostCertCheck(); err != nil {
		log.WithError(err).Warn("Couldn't force a host cert check")
	}

	return &pb.ServiceCertRemoveDomainResponse{}, nil
}

func (a Api) ServiceCertReset(ctx context.Context, in *pb.ServiceCertResetRequest) (*pb.ServiceCertResetResponse, error) {
	if err := UpdateConfigExclusive(func(newCfg *Config) {
		newCfg.HostCert = false
		newCfg.HostDomain = ""
		newCfg.HostDocRoot = ""
		newCfg.HostDomainKey = ""
		newCfg.HostAccountKey = ""
		newCfg.HostExtraNames = nil
		newCfg.HostDomainCertPem = ""
		newCfg.IssuerCertPem = ""
		newCfg.Insecure = true
	}); err != nil {
		return &pb.ServiceCertResetResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	return &pb.ServiceCertResetResponse{}, nil
}

func (a Api) AutoSSLSetEnabled(ctx context.Context, in *pb.AutoSSLSetEnabledRequest) (*pb.AutoSSLSetEnabledResponse, error) {
	if err := UpdateConfigExclusive(func(newCfg *Config) {
		newCfg.AutoSSL = in.NewState
	}); err != nil {
		return &pb.AutoSSLSetEnabledResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	return &pb.AutoSSLSetEnabledResponse{}, nil
}

func certificatesFromNV(data map[string]*common.NVDataDomainCerts) []*pb.SSLCertificate {
	doms := []*pb.SSLCertificate{}
	for _, v := range data {
		doms = append(doms, &pb.SSLCertificate{
			Domain:   v.Domain,
			AltNames: v.AltNames,
			Url:      v.OrderUrl,
			Expiry:   v.CertExpiry,
			CertId:   v.CertId,
			KeyId:    v.KeyId,
			CertPem:  v.DomainCert,
		})
	}
	return doms
}

func (a Api) AutoSSLRunForUser(ctx context.Context, in *pb.AutoSSLRunForUserRequest) (*pb.AutoSSLRunForUserResponse, error) {
	newCerts, debug, err := processAutoSSLForAccount(in.User, nil, in.Retry)
	if err != nil {
		return &pb.AutoSSLRunForUserResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	restartApacheIfNecessary()

	return &pb.AutoSSLRunForUserResponse{
		Certificates: certificatesFromNV(newCerts),
		Debug:        debug,
	}, nil
}

func (a Api) SSLListCertificates(ctx context.Context, in *pb.SSLListCertificatesRequest) (*pb.SSLListCertificatesResponse, error) {
	cp, err := makeCpanelClient(in.User)
	if err != nil {
		return &pb.SSLListCertificatesResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	data, err := common.GetAndParseNVData(cp)
	if err != nil {
		return &pb.SSLListCertificatesResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	return &pb.SSLListCertificatesResponse{
		Certificates: certificatesFromNV(data.Certs),
	}, nil
}

func (a Api) SSLIssueCertificate(ctx context.Context, in *pb.SSLIssueCertificateRequest) (*pb.SSLIssueCertificateResponse, error) {
	newCerts, debug, err := processAutoSSLForAccount(in.User, in.Names, false)
	if err != nil {
		return &pb.SSLIssueCertificateResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	restartApacheIfNecessary()

	return &pb.SSLIssueCertificateResponse{
		NewCertificates: certificatesFromNV(newCerts),
		Debug:           debug,
	}, nil
}

func (a Api) SSLRemoveCertificate(ctx context.Context, in *pb.SSLRemoveCertificateRequest) (*pb.SSLRemoveCertificateResponse, error) {
	deleted, err := removeCertificates(in.User, in.Names)
	if err != nil {
		return &pb.SSLRemoveCertificateResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	restartApacheIfNecessary()

	return &pb.SSLRemoveCertificateResponse{
		Removed: certificatesFromNV(deleted),
	}, nil
}

func (a Api) SSLReuseCertificate(ctx context.Context, in *pb.SSLReuseCertificateRequest) (*pb.SSLReuseCertificateResponse, error) {
	if !lockUser(in.User) {
		return &pb.SSLReuseCertificateResponse{Errors: a.makeError("Unable to acquire lock on user")}, nil
	}
	defer unlockUser(in.User)

	cl, err := makeCpanelClient(in.User)
	if err != nil {
		return &pb.SSLReuseCertificateResponse{Errors: a.makeError("Unable to create cPanel client", err.Error())}, nil
	}

	data, err := common.GetAndParseNVData(cl)
	if err != nil {
		return &pb.SSLReuseCertificateResponse{Errors: a.makeError("Unable to parse user data", err.Error())}, nil
	}

	if err := common.MapCertificateReuse(cl, data, in.SourceDomain, in.TargetDomain); err != nil {
		return &pb.SSLReuseCertificateResponse{Errors: a.makeError("Failed to map certificate re-use", err.Error())}, nil
	}

	return &pb.SSLReuseCertificateResponse{}, nil
}

func (a Api) SSLRemoveReuseCertificate(ctx context.Context, in *pb.SSLRemoveReuseCertificateRequest) (*pb.SSLRemoveReuseCertificateResponse, error) {
	if !lockUser(in.User) {
		return &pb.SSLRemoveReuseCertificateResponse{Errors: a.makeError("Unable to acquire lock on user")}, nil
	}
	defer unlockUser(in.User)

	cl, err := makeCpanelClient(in.User)
	if err != nil {
		return &pb.SSLRemoveReuseCertificateResponse{Errors: a.makeError("Unable to create cPanel client", err.Error())}, nil
	}

	data, err := common.GetAndParseNVData(cl)
	if err != nil {
		return &pb.SSLRemoveReuseCertificateResponse{Errors: a.makeError("Unable to parse user data", err.Error())}, nil
	}

	if err := common.UnmapCertificateReuse(cl, data, in.TargetDomain); err != nil {
		return &pb.SSLRemoveReuseCertificateResponse{Errors: a.makeError("Failed to map certificate re-use", err.Error())}, nil
	}

	return &pb.SSLRemoveReuseCertificateResponse{}, nil
}

func (a Api) SSLReuseList(ctx context.Context, in *pb.SSLReuseListRequest) (*pb.SSLReuseListResponse, error) {
	cl, err := makeCpanelClient(in.User)
	if err != nil {
		return &pb.SSLReuseListResponse{Errors: a.makeError("Unable to create cPanel client", err.Error())}, nil
	}

	data, err := common.GetAndParseNVData(cl)
	if err != nil {
		return &pb.SSLReuseListResponse{Errors: a.makeError("Unable to parse user data", err.Error())}, nil
	}

	return &pb.SSLReuseListResponse{
		Reuses: data.Reuses,
	}, nil
}

func (a Api) SSLReinstallCertificate(ctx context.Context, in *pb.SSLReinstallRequest) (*pb.SSLReinstallResponse, error) {
	cl, err := makeCpanelClient(in.User)
	if err != nil {
		return &pb.SSLReinstallResponse{Errors: a.makeError("Unable to create cPanel client", err.Error())}, nil
	}

	data, err := common.GetAndParseNVData(cl)
	if err != nil {
		return &pb.SSLReinstallResponse{Errors: a.makeError("Unable to parse user data", err.Error())}, nil
	}

	certs, ok := data.Certs[in.Domain]
	if !ok {
		return &pb.SSLReinstallResponse{
			Errors: a.makeError(fmt.Sprintf("There is no domain %s on this account with a certificate", in.Domain)),
		}, nil
	}

	_, errs := cpanelcgi.ReinstallCertificate(cl, data, certs, in.PreferredIssuer)
	if errs != nil {
		return &pb.SSLReinstallResponse{
			Errors: a.makeError(errs.GatherErrors()...),
		}, nil

	}
	return &pb.SSLReinstallResponse{}, nil
}

func (a Api) SSLDoRenewals(ctx context.Context, in *pb.SSLDoRenewalsRequest) (*pb.SSLDoRenewalsResponse, error) {
	renewed, err := processRenewalsForAccount(whmCl, in.User, in.Force, in.DryRun, in.VirtualHost)
	if err != nil {
		return &pb.SSLDoRenewalsResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	if !in.DryRun {
		restartApacheIfNecessary()
	}

	return &pb.SSLDoRenewalsResponse{
		Renewed: certificatesFromNV(renewed),
	}, nil
}

func firstOf(arr ...string) string {
	for _, v := range arr {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a Api) ConfigGetEntries(ctx context.Context, in *pb.ConfigGetEntriesRequest) (*pb.ConfigGetEntriesResponse, error) {
	if config.AutoSSLSkipPatterns == nil {
		config.AutoSSLSkipPatterns = []string{}
	}
	skipPatternsEncoded, _ := json.Marshal(config.AutoSSLSkipPatterns)

	cryptoParams := client.GetCryptoParams()

	return &pb.ConfigGetEntriesResponse{
		Entries: []*pb.ConfigEntry{
			{
				Name:        "Administrative Emails Destination",
				Description: "Where administrative emails should be sent",
				Type:        "email",
				Key:         "email_admin_destination",
				Value:       firstOf(config.EmailAdminDest, GetAdminEmail()),
			},
			{
				Name:        "Deferred restarts",
				Description: "Whether to defer Apache restarts until the end of a renewal process. This is highly reccommended if you use AutoSSL.",
				Type:        "bool",
				Key:         "deferred_restarts",
				Value:       fmt.Sprintf("%v", config.DeferredRestarts),
			},
			{
				Name:        "Service Certificates",
				Description: "Whether to issue service certificates if no valid ones are present. https://cpanel.fleetssl.com/docs/for-admins/service-certificates/",
				Type:        "bool",
				Key:         "service_certificates",
				Value:       fmt.Sprintf("%v", config.HostCert),
			},
			{
				Name:        "Automatic SSL (AutoSSL)",
				Description: "Whether to install certificates periodically on accounts where no existing certificates are detected. https://cpanel.fleetssl.com/docs/for-admins/autossl/",
				Type:        "bool",
				Key:         "autossl",
				Value:       fmt.Sprintf("%v", config.AutoSSL),
			},
			{
				Name:        "Report Successes",
				Description: "Whether to list successful renewals in a periodic admin report",
				Type:        "bool",
				Key:         "report_successes",
				Value:       fmt.Sprintf("%v", config.Reporting.Successes),
			},
			{
				Name:        "Report Failures",
				Description: "Whether to list failures in a periodic admin report",
				Type:        "bool",
				Key:         "report_failures",
				Value:       fmt.Sprintf("%v", config.Reporting.Failures),
			},
			{
				Name:        "Disable Renewal Success Emails",
				Description: "Whether to disable renewal success emails for all users, regardless of their settings",
				Type:        "bool",
				Key:         "disable_success_mail",
				Value:       fmt.Sprintf("%v", config.DisableSuccessMail),
			},
			{
				Name:        "Disable All Renewal Emails",
				Description: "Whether to disable all renewal (success + failure) emails for all users, regardless of their settings",
				Type:        "bool",
				Key:         "disable_mail",
				Value:       fmt.Sprintf("%v", config.DisableRenewalMail),
			},
			{
				Name:        "Challenge Methods",
				Description: "Which ACME challenge methods to allow to validate SSL certificates",
				Type:        "string",
				Key:         "challenge_methods",
				Value:       strings.Join(config.ChallengeMethods, ","),
			},
			{
				Name:        "Preferred Issuer/Alternate Chain",
				Description: "If multiple certificate chains are offered, prefer the one where the top-most certificate is issued by this Subject Common Name",
				Type:        "string",
				Key:         "preferred_issuer_cn",
				Value:       config.PreferredIssuerCN,
			},
			{
				Name: "AutoSSL Skip Patterns",
				Description: `An array of regex patterns of hostnames to avoid when ` +
					`processing AutoSSL. Pass as a JSON array of strings, e.g. ` +
					`["^mail\..*", ".*\.foo\.com$"]`,
				Type:  "string",
				Key:   "autossl_skip_patterns",
				Value: string(skipPatternsEncoded),
			},
			{
				Name:        "AutoSSL Skip Proxy Subdomains",
				Description: "Whether to skip proxy subdomains when issuing certificates via AutoSSL.",
				Type:        "bool",
				Key:         "autossl_skip_proxy_subdomains",
				Value:       fmt.Sprintf("%v", config.AutoSSLSkipProxy),
			},
			{
				Name: "Default Key Type",
				Description: "What key type to use by default for ACME account keys and certificate private keys. " +
					"Always used for AutoSSL and service certificates. Users have the option to choose other " +
					"key types via the user interface.",
				Type:  "string",
				Key:   "default_key_type",
				Value: cryptoParams.String(),
			},
		},
	}, nil
}

func (a Api) ConfigUpdateEntries(ctx context.Context, in *pb.ConfigUpdateEntriesRequest) (*pb.ConfigUpdateEntriesResponse, error) {
	log.WithField("entries", in.Entries).Info("Got a config update request")

	if err := UpdateConfigExclusive(func(newCfg *Config) {
		for _, entry := range in.Entries {
			switch entry.Key {
			case "email_admin_destination":
				newCfg.EmailAdminDest = entry.Value
			case "deferred_restarts":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.DeferredRestarts = b
			case "report_successes":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.Reporting.Successes = b
			case "report_failures":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.Reporting.Failures = b
			case "service_certificates":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.HostCert = b
			case "autossl":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.AutoSSL = b
			case "disable_success_mail":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.DisableSuccessMail = b
			case "disable_mail":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.DisableRenewalMail = b
			case "challenge_methods":
				newCfg.ChallengeMethods = strings.Split(strings.TrimSpace(entry.Value), ",")
			case "preferred_issuer_cn":
				newCfg.PreferredIssuerCN = strings.TrimSpace(entry.Value)
			case "autossl_skip_patterns":
				var skipPatterns []string
				if err := json.Unmarshal([]byte(entry.Value), &skipPatterns); err == nil {
					newCfg.AutoSSLSkipPatterns = skipPatterns
				} else {
					log.WithField("key", entry.Key).WithError(err).Warn("Invalid JSON, ignoring")
				}
			case "autossl_skip_proxy_subdomains":
				b, _ := strconv.ParseBool(entry.Value) // discard error and set to false
				newCfg.AutoSSLSkipProxy = b
			case "default_key_type":
				params, err := client.KeyTypeStringToParams(entry.Value)
				if err == nil {
					newCfg.CryptoKeyType = string(params.Type)
					newCfg.CryptoEcdsaCurve = strings.ToLower(params.Curve.Params().Name)
					newCfg.CryptoRsaKeySize = params.RsaKeySize
				} else {
					log.WithField("key", entry.Key).WithError(err).Warn("Invalid key type, ignoring")
				}
			default:
				log.WithField("key", entry.Key).Warn("Not a known key to update, ignoring")
			}
		}
	}); err != nil {
		return &pb.ConfigUpdateEntriesResponse{
			Errors: a.makeError(err.Error()),
		}, nil
	}

	return &pb.ConfigUpdateEntriesResponse{}, nil
}

// Reporting
func (a Api) ReportingForceRun(ctx context.Context, in *pb.ReportingForceRunRequest) (*pb.ReportingForceRunResponse, error) {
	select {
	case <-time.After(5 * time.Second):
		return &pb.ReportingForceRunResponse{
			Errors: []*pb.Error{
				{
					Error: "Timed out trying to force report send",
				},
			},
		}, nil
	case forceReportCh <- struct{}{}:
		return &pb.ReportingForceRunResponse{}, nil
	}
}

func (a Api) RpcForceReload(ctx context.Context, in *pb.RpcForceReloadRequest) (*pb.RpcForceReloadResponse, error) {
	log.Info("Got request to force-reload rpc server")
	var err error
	select {
	case rpcRestartCh <- struct{}{}:
		log.Info("force-reloaded RPC server")
		break
	case <-time.After(5 * time.Second):
		log.Warn("force-reload timed out")
		err = errors.New("Force-reload timed out")
		break
	}
	if err != nil {
		return &pb.RpcForceReloadResponse{Errors: []*pb.Error{{Error: err.Error()}}}, nil
	}
	return &pb.RpcForceReloadResponse{}, nil

}

func (a Api) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PingResponse, error) {
	log.Info("Got ping via rpc")

	bail := func(err error) (*pb.PingResponse, error) {
		return &pb.PingResponse{
			Errors: []*pb.Error{
				&pb.Error{Error: err.Error()},
			},
		}, nil
	}

	// Test BoltDB functionality, write, read, delete
	key := time.Now().String()
	if err := dbPutBucket("self_test", key, key); err != nil {
		return bail(err)
	}
	var out string
	if err := dbFetchBucket("self_test", key, &out); err != nil {
		return bail(err)
	}
	if out != key {
		return bail(errors.New("BoltDB returned wrong value"))
	}
	if err := dbRemoveBucket("self_test", key); err != nil {
		return bail(err)
	}

	return &pb.PingResponse{}, nil
}
