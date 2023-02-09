package clapi

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
)

func SSL() cli.Command {
	return cli.Command{
		Name:   "ssl",
		Usage:  "Manage SSL certificates for a user",
		Before: InitRpc,
		After:  CloseRpc,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "user",
				Usage: "Username of user to manage",
			},
		},
		Subcommands: []cli.Command{
			cli.Command{
				Name:   "list",
				Usage:  "List certificates configured for user",
				Action: listUserSSL,
			},
			cli.Command{
				Name:   "issue",
				Usage:  "Issue certificates for a set of names",
				Action: issueUserSSL,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "verbose",
						Usage: "Show verbose information about what happened during the request",
					},
				},
			},
			{
				Name:   "reinstall",
				Usage:  "Reinstall an existing certificate by primary domain name",
				Action: reinstallUserSSL,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "preferred-issuer",
						Usage: "Specify a preferred issuer/alternate chain to use when re-installing",
					},
				},
			},
			cli.Command{
				Name:   "remove",
				Usage:  "Remove certificate by primary domain names",
				Action: removeUserSSL,
			},
			cli.Command{
				Name:   "renew",
				Usage:  "Renews account certificates, only if they are within expiry range",
				Action: renewUserSSL,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "virtualhost",
						Usage: "Only try to renew this specific virtualhost",
					},
					cli.BoolFlag{
						Name:  "force",
						Usage: "Force live renewal of selected domains",
					},
					cli.BoolFlag{
						Name:  "dry-run",
						Usage: "Perform a dry (test) run of renewal, using the Let's Encrypt staging server",
					},
				},
			},
			cli.Command{
				Name:   "reuse",
				Usage:  "Re-uses a certificate from one virtual host on another virtual host",
				Action: mapReuse,
				Flags: []cli.Flag{
					cli.StringFlag{Name: "source"},
					cli.StringFlag{Name: "target"},
				},
			},
			cli.Command{
				Name:   "remove-reuse",
				Usage:  "Removes a re-use from a virtual host",
				Action: unmapReuse,
				Flags: []cli.Flag{
					cli.StringFlag{Name: "target"},
				},
			},
			cli.Command{
				Name:   "list-reuses",
				Usage:  "Lists all certificate re-uses configured on the account",
				Action: listReuses,
			},
		},
	}
}

func printCerts(ctx *cli.Context, certs []*pb.SSLCertificate) error {
	if hasTemplate(ctx) {
		return printTemplate(ctx, certs)
	}

	if len(certs) == 0 {
		log.Println("No certificates were returned")
		return nil
	}

	log.Printf("%d certificates were returned", len(certs))

	for _, v := range certs {
		block, _ := pem.Decode([]byte(v.CertPem))
		crt, _ := x509.ParseCertificate(block.Bytes)

		log.Printf("Domain: %s", v.Domain)
		log.Printf("\tRequested AltNames: %v", v.AltNames)
		log.Printf("\tExpiry: %v", time.Unix(v.Expiry, 0).String())
		log.Printf("\tURL: %s", v.Url)
		if v.CertId != "" {
			log.Printf("\tCert ID: %s", v.CertId)
		}
		if v.KeyId != "" {
			log.Printf("\tKey ID: %s", v.KeyId)
		}
		if crt != nil {
			log.Printf("\tActual DNS Names on Certificate: %v", crt.DNSNames)
		}
	}

	return nil
}

func listUserSSL(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	if user == "" {
		return errors.New("Please pass a --user")
	}

	certs, err := cl.SSLListCertificates(clCtx, &pb.SSLListCertificatesRequest{
		User: user,
	})
	if err != nil {
		return err
	}

	if err := handleError(certs); err != nil {
		return err
	}

	return printCerts(ctx, certs.Certificates)

}

func issueUserSSL(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	if user == "" {
		return errors.New("Please pass a --user")
	}

	if !ctx.Args().Present() {
		return errors.New("Please provide space-separated list of names to issue certificates for")
	}

	certs, err := cl.SSLIssueCertificate(clCtx, &pb.SSLIssueCertificateRequest{
		User:  user,
		Names: []string(ctx.Args()),
	})
	if err != nil {
		return err
	}

	if err := handleError(certs); err != nil {
		return err
	}

	if ctx.Bool("verbose") {
		log.Printf("Additional information (--verbose):")
		printDebugMap(certs.Debug)
	}

	return printCerts(ctx, certs.NewCertificates)
}

func removeUserSSL(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	if user == "" {
		return errors.New("Please pass a --user")
	}

	if !ctx.Args().Present() {
		return errors.New("Please provide space-separated list of primary certificate names")
	}

	resp, err := cl.SSLRemoveCertificate(clCtx, &pb.SSLRemoveCertificateRequest{
		Names:       []string(ctx.Args()),
		User:        user,
		OnlyManaged: true,
	})

	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return nil
	}

	return printCerts(ctx, resp.Removed)
}

func renewUserSSL(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	if user == "" {
		return errors.New("Please pass a --user")
	}

	resp, err := cl.SSLDoRenewals(clCtx, &pb.SSLDoRenewalsRequest{
		User:        user,
		Force:       ctx.Bool("force"),
		DryRun:      ctx.Bool("dry-run"),
		VirtualHost: ctx.String("virtualhost"),
	})

	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return printCerts(ctx, resp.Renewed)
}

func reinstallUserSSL(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	if user == "" {
		return errors.New("Please pass a --user")
	}
	if len(ctx.Args()) != 1 {
		return errors.New("Please provide a primary domain to reinstall certificates for")
	}

	resp, err := cl.SSLReinstallCertificate(clCtx, &pb.SSLReinstallRequest{
		User:            user,
		Domain:          ctx.Args()[0],
		PreferredIssuer: ctx.String("preferred-issuer"),
	})
	if err != nil {
		return err
	}

	return handleError(resp)
}

func mapReuse(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	source := ctx.String("source")
	target := ctx.String("target")
	if user == "" || source == "" || target == "" {
		return errors.New("Please pass a --user, a --source domain and a --target domain")
	}

	resp, err := cl.SSLReuseCertificate(clCtx, &pb.SSLReuseCertificateRequest{
		User:         user,
		SourceDomain: source,
		TargetDomain: target,
	})
	if err != nil {
		return err
	}
	return handleError(resp)
}

func unmapReuse(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	target := ctx.String("target")
	if user == "" || target == "" {
		return errors.New("Please pass a --user and a --target domain")
	}

	resp, err := cl.SSLRemoveReuseCertificate(clCtx, &pb.SSLRemoveReuseCertificateRequest{
		User:         user,
		TargetDomain: target,
	})
	if err != nil {
		return err
	}
	return handleError(resp)
}

func listReuses(ctx *cli.Context) error {
	user := ctx.GlobalString("user")
	if user == "" {
		return errors.New("Please pass a --user")
	}

	resp, err := cl.SSLReuseList(clCtx, &pb.SSLReuseListRequest{
		User: user,
	})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	if hasTemplate(ctx) {
		return printTemplate(ctx, resp.Reuses)
	}

	log.Printf("%d re-uses found.", len(resp.Reuses))
	for target, source := range resp.Reuses {
		log.Printf("Virtual host '%s' re-uses the certificate from '%s'", target, source)
	}

	return nil
}
