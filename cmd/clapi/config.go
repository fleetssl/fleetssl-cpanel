package clapi

import (
	"errors"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
)

func Config() cli.Command {
	return cli.Command{
		Name:   "config",
		Usage:  "Manage plugin configuration entries",
		Before: InitRpc,
		After:  CloseRpc,
		Subcommands: []cli.Command{
			cli.Command{
				Name:   "list",
				Usage:  "List configuration entries",
				Action: configList,
			},
			cli.Command{
				Name:   "set",
				Usage:  "Set configuration entries",
				Action: configSet,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name: "key",
					},
					cli.StringFlag{
						Name: "value",
					},
				},
			},
			cli.Command{
				Name:   "rpc-force-reload",
				Usage:  "Force the RPC server to reload",
				Action: configRpcForceReload,
			},
		},
	}
}

func configList(ctx *cli.Context) error {
	resp, err := cl.ConfigGetEntries(clCtx, &pb.ConfigGetEntriesRequest{})
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}
	if len(resp.GetEntries()) == 0 {
		return nil
	}

	if hasTemplate(ctx) {
		return printTemplate(ctx, resp.GetEntries())
	}
	for _, entry := range resp.GetEntries() {
		log.Printf("Name:        %s", entry.Name)
		log.Printf("Description: %s", entry.Description)
		log.Printf("Key:         %s", entry.Key)
		log.Printf("Value:       %s", entry.Value)
		log.Println("------------")
	}

	return nil
}

func configSet(ctx *cli.Context) error {
	if ctx.String("key") == "" || ctx.String("value") == "" {
		return errors.New("--key and --value must be present")
	}

	req := &pb.ConfigUpdateEntriesRequest{Entries: []*pb.ConfigEntry{&pb.ConfigEntry{
		Key:   ctx.String("key"),
		Value: ctx.String("value"),
	}}}

	resp, err := cl.ConfigUpdateEntries(clCtx, req)
	if err != nil {
		return err
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}

func configRpcForceReload(ctx *cli.Context) error {
	log.Info("Please disregard any errors relating to 'client transport was broken', this is normal for this operation!")

	resp, err := cl.RpcForceReload(clCtx, &pb.RpcForceReloadRequest{})
	if err != nil {
		return nil
	}

	if err := handleError(resp); err != nil {
		return err
	}

	return nil
}
