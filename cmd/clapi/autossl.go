package clapi

import (
	"errors"
	"sort"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
)

func AutoSSL() cli.Command {
	return cli.Command{
		Name:   "autossl",
		Usage:  "Manage the plugin AutoSSL feature",
		Before: InitRpc,
		After:  CloseRpc,
		Subcommands: []cli.Command{
			cli.Command{
				Name:   "enable",
				Usage:  "Enable AutoSSL",
				Action: enableAutoSSL,
			},
			cli.Command{
				Name:   "disable",
				Usage:  "Disable AutoSSL",
				Action: disableAutoSSL,
			},
			cli.Command{
				Name:   "run-for-user",
				Usage:  "Run AutoSSL for a single user",
				Action: runAutoSSLForUser,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:   "retry",
						Usage:  "Retry on DVC preflight failures (will block for a long time, only useful for testing)",
						Hidden: true,
					},
					cli.BoolFlag{
						Name:  "verbose",
						Usage: "Show extra information about what happened during the request",
					},
				},
			},
		},
	}
}

func disableAutoSSL(ctx *cli.Context) error {
	resp, err := cl.AutoSSLSetEnabled(clCtx, &pb.AutoSSLSetEnabledRequest{NewState: false})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func enableAutoSSL(ctx *cli.Context) error {
	resp, err := cl.AutoSSLSetEnabled(clCtx, &pb.AutoSSLSetEnabledRequest{NewState: true})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func runAutoSSLForUser(ctx *cli.Context) error {
	user := ctx.Args().First()
	if user == "" {
		return errors.New("Please pass a username")
	}

	req := &pb.AutoSSLRunForUserRequest{
		User:  user,
		Retry: ctx.Bool("retry"),
	}

	resp, err := cl.AutoSSLRunForUser(clCtx, req)
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	if ctx.Bool("verbose") {
		log.Printf("Additional information (--verbose):")
		printDebugMap(resp.Debug)
	}

	return printCerts(ctx, resp.Certificates)
}

func printDebugMap(m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		log.Printf("- [%s]: %s", k, m[k])
	}
}
