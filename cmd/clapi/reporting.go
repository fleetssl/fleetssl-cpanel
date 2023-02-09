package clapi

import (
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	"gopkg.in/urfave/cli.v1"
)

func Reporting() cli.Command {
	return cli.Command{
		Name:   "reporting",
		Usage:  "Manage the reporting feature",
		Before: InitRpc,
		After:  CloseRpc,
		Subcommands: []cli.Command{
			cli.Command{
				Name:   "send-now",
				Usage:  "Forces the periodic admin report to be sent now. Will reset the time to now.",
				Action: sendReportNow,
			},
		},
	}
}

func sendReportNow(ctx *cli.Context) error {
	resp, err := cl.ReportingForceRun(clCtx, &pb.ReportingForceRunRequest{})
	if err != nil {
		return err
	}
	if err := handleError(resp); err != nil {
		return err
	}
	return nil
}
