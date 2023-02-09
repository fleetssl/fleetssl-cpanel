package clapi

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
)

func Hostcert() cli.Command {
	return cli.Command{
		Name:   "hostcert",
		Usage:  "Add/list/remove host service certificates for cPanel",
		Before: InitRpc,
		After:  CloseRpc,
		Subcommands: []cli.Command{
			cli.Command{
				Name:   "enable",
				Usage:  "Enable Let's Encrypt-based service certificates",
				Action: enableHostCerts,
			},
			cli.Command{
				Name:   "disable",
				Usage:  "Disable Let's Encrypt-based service certificates",
				Action: disableHostCerts,
			},
			cli.Command{
				Name:   "list",
				Usage:  "List current names for service certificates",
				Action: listHostCerts,
			},
			cli.Command{
				Name:   "add",
				Usage:  "Add another name for service certificates",
				Action: addHostCert,
			},
			cli.Command{
				Name:   "remove",
				Usage:  "Remove a name from service certificates",
				Action: removeHostCert,
			},
			cli.Command{
				Name:   "reset",
				Usage:  "Reset all of the service certificate settings",
				Action: resetHostCert,
			},
		},
	}
}

func listHostCerts(ctx *cli.Context) error {
	doms, err := cl.ServiceCertListDomains(clCtx, &pb.ServiceCertListDomainsRequest{})
	if err != nil {
		return err
	}

	if err := handleError(doms); err != nil {
		return err
	}

	if hasTemplate(ctx) {
		return printTemplate(ctx, doms.Domains)
	}

	for _, v := range doms.Domains {
		log.Println(v)
	}
	return nil
}

func addHostCert(ctx *cli.Context) error {
	req := &pb.ServiceCertAddDomainRequest{
		Domains: []string(ctx.Args()),
	}

	resp, err := cl.ServiceCertAddDomain(clCtx, req)
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func removeHostCert(ctx *cli.Context) error {
	resp, err := cl.ServiceCertRemoveDomain(clCtx, &pb.ServiceCertRemoveDomainRequest{
		Domains: []string(ctx.Args()),
	})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func disableHostCerts(ctx *cli.Context) error {
	resp, err := cl.ServiceCertSetEnabled(clCtx, &pb.ServiceCertSetEnabledRequest{NewState: false})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func enableHostCerts(ctx *cli.Context) error {
	resp, err := cl.ServiceCertSetEnabled(clCtx, &pb.ServiceCertSetEnabledRequest{NewState: true})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func resetHostCert(ctx *cli.Context) error {
	resp, err := cl.ServiceCertReset(clCtx, &pb.ServiceCertResetRequest{})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}
