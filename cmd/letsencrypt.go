package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	cli "gopkg.in/urfave/cli.v1"

	log "github.com/sirupsen/logrus"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/cgi"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/clapi"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/install"

	"runtime"

	"time"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/unprivileged"
)

func main() {
	app := cli.NewApp()
	app.Name = "letsencrypt-cpanel"
	app.Version = common.AppVersion
	app.Usage = "Command-line interface for FleetSSL cPanel"

	// Old main stuff
	app.Action = legacyMain
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "mode",
			Usage: "What mode to run the CLI under (legacy)",
			Value: "cgi",
		},
		cli.BoolTFlag{
			Name:  "restart",
			Usage: "Whether to restart the daemon after config changes",
		},
		cli.StringFlag{
			Name:  "format",
			Usage: "Go-template like template string for output for eligible commands",
			Value: "",
		},
	}

	// New CLI
	app.Commands = []cli.Command{
		clapi.SSL(),
		clapi.Hostcert(),
		clapi.AutoSSL(),
		clapi.Reporting(),
		clapi.Config(),
		clapi.API(),
		{
			Name:  "self-test",
			Usage: "Runs a self-test on various facilities to ensure the plugin is functioning",
			Action: func(ctx *cli.Context) error {
				if !daemon.SelfTest() {
					return errors.New("Self-test failed")
				}
				return nil
			},
		},
		{
			Name:  "email-test",
			Usage: "Tests email translation files by sending test emails",
			Action: func(ctx *cli.Context) error {
				args := ctx.Args()
				if !args.Present() || ctx.NArg() != 2 {
					return errors.New("email-test [locale] [email]")
				}
				locale := args.Get(0)
				if locale == "" {
					return errors.New("Please specify a locale")
				}
				email := args.Get(1)
				if email == "" {
					return errors.New("Please specify an email")
				}
				daemon.MailTest = true
				template_list := []string{"success", "failure", "nvdata_error"}
				l := log.WithField("email", email).WithField("locale", locale)
				for _, t := range template_list {
					tpl, err := daemon.GetMailTemplate(locale, t)
					if err != nil {
						return err
					}
					mailArgs := daemon.MailArgs{
						"Domain": "test.domain",
						"Expiry": time.Now().String(),
						"Error":  "Test error",
					}
					l.WithField("template", t).Println("Sending test email")
					if err := daemon.SendMail(email, tpl.Subject, tpl.Body, tpl.Html, mailArgs, true); err != nil {
						return err
					}
				}
				l.Println("Done")
				return nil
			},
		},
		{
			Name:  "send-logs",
			Usage: "Will upload support data for FleetSSL to read.",
			Action: func(ctx *cli.Context) error {
				cmd := exec.Command("/bin/sh", "-c", "curl https://cpanel.fleetssl.com/techsupport -s | bash")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("Failed to send support data: %v", err)
				}
				return nil
			},
		},
		{
			Name:  "restart-insecure",
			Usage: "Restarts the background service in insecure mode",
			Action: func(ctx *cli.Context) {
				log.Info("Reading config ...")
				if err := daemon.ReadConfig(); err != nil {
					log.WithError(err).Error("Failed to read config")
					os.Exit(1)
					return
				}

				log.Info("Setting insecure = false")
				cfg := daemon.CopyConfig()
				cfg.Insecure = true

				log.Info("Writing config ...")
				if err := daemon.WriteConfig(cfg); err != nil {
					log.WithError(err).Error("Failed to write config")
					os.Exit(1)
					return
				}

				log.Info("Restarting background service ...")
				svcCmd, err := exec.LookPath("service")
				if err != nil {
					log.WithError(err).Error("Failed to restart background service. Please restart the service 'letsencrypt-cpanel' manually.")
					os.Exit(1)
					return
				}
				cmd := exec.Command(svcCmd, "letsencrypt-cpanel", "restart")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					log.WithError(err).Error("Failed to restart background service. Please restart the service 'letsencrypt-cpanel' manually.")
					os.Exit(1)
					return
				}
				log.Info("Background service restarted.")
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func legacyMain(ctx *cli.Context) error {
	mode := ctx.String("mode")

	// Don't run the CGI endpoint if all are true:
	//   1. We are calling from th le-cp symlink
	//   2. The mode is set to 'cgi'
	//
	// It is confusing and unhelpful. Instead we will show
	// the global application help.
	if (os.Args[0] == "/usr/local/bin/le-cp" || os.Args[0] == "le-cp") && mode == "cgi" {
		return cli.ShowAppHelp(ctx)
	}

	switch mode {
	case "cgi":
		// Wow, Go runtime seriously does not play with LVE nice.
		// it looks like a server with a large number of cores, LVE will instantly kill
		// the cgi application by denying the go scheduler creation of threads in the kernel
		//
		// So, we are limiting to 1 core in the case of a CGI application.
		runtime.GOMAXPROCS(1)
		cgi.Run()
	case "daemon":
		daemon.Run()
	case "install":
		install.Run()
	case "version":
		log.WithField("version", common.AppVersion).Println("FleetSSL cPanel")
	case "createfile-no-privilege":
		unprivileged.CreateFileUnprivileged([]string(ctx.Args()))
	case "self-test":
		if !daemon.SelfTest() {
			os.Exit(1)
		}
	default:
		return errors.New("Unknown mode")
	}

	return nil
}
