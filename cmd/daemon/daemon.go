package daemon

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/juju/ratelimit"
	log "github.com/sirupsen/logrus"

	"runtime"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	"github.com/boltdb/bolt"
	"github.com/fatih/color"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"github.com/letsencrypt-cpanel/cpanelgo/whm"
)

const (
	DbCheckInterval  = 5
	RenewalsInterval = 12 // hours
)

var db *bolt.DB
var whmCl whm.WhmApi

var working = map[string]time.Time{}
var muWorking sync.Mutex

var acmeRegistrationsLimit *ratelimit.Bucket

func InitClients() error {
	var err error
	if err = ReadConfig(); err != nil {
		return fmt.Errorf("Error reading config: %v", err)
	}

	whmCl, err = common.MakeWhmClient(config.Insecure)
	if err != nil {
		return fmt.Errorf("Error making WHM client: %v", err)
	}

	return nil
}

func Run() {
	log.WithFields(log.Fields{
		"Version": common.AppVersion,
		"Arch":    runtime.GOARCH,
	}).Println("Daemon starting")
	var err error

	exitCh := make(chan error)    // errors from goroutines
	sigCh := make(chan os.Signal) // catches signals from os to stop
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP, os.Interrupt)

	// Bring up web first because chkservd is looking for it
	go listen(exitCh)

	if err = InitClients(); err != nil {
		log.WithError(err).Error("Initialising clients")
		return
	}

	if err := openBolt(); err != nil {
		log.WithError(err).Error("Failed to open database, trying again once more")
		if err := openBolt(); err != nil {
			log.WithError(err).Error("Failed to open database again, giving up")
			return
		}
	}

	defer func() {
		tp := time.AfterFunc(5*time.Second, func() {
			log.Fatal("DB close timed out")
		})
		db.Close()
		tp.Stop()
		log.WithField("Version", common.AppVersion).Println("Daemon exiting")
		os.Exit(0)
	}()

	err = ListenRpc("0.0.0.0:5960", Api{}, nil)
	if err != nil {
		log.WithError(err).Println("Failed to start RPC server")
		return
	}

	go processRenewals(exitCh)
	go processAutoSSLDeferred()
	go checkHostCert(exitCh)
	go runReports(exitCh)
	go vacuumFlags()
	go processWorkarounds()

	for {
		select {
		case err := <-exitCh:
			log.WithError(err).Error("Fatal error from goroutine")
			return
		case sig := <-sigCh:
			log.WithField("Signal", sig).Info("Caught signal")
			if sig == syscall.SIGHUP {
				log.Info("Reloading config")
				if err := ReadConfig(); err != nil {
					log.WithError(err).Error("Failed to reload config")
					return
				}
				continue
			}
			return
		}
	}
}

func SelfTest() bool {
	tests := []struct {
		Description string
		Test        func() error
	}{
		{
			"Can read config",
			func() error {
				return ReadConfig()
			},
		},
		{
			"Can connect to Let's Encrypt",
			func() error {
				_, err := common.NewAcmeClient(common.BoulderUrl)
				return err
			},
		},
		{
			"Can talk to WHM API",
			func() error {
				whmCl, err := common.MakeWhmClient(config.Insecure)
				if err != nil {
					return err
				}

				resp, err := whmCl.Version()
				if err != nil {
					return err
				}

				if resp.Data.Version == "" {
					return errors.New("Unable to fetch version from WHMAPI1")
				}

				return nil
			},
		},
		{
			"Can talk to plugin RPC",
			func() error {
				conn, ctx, err := common.CreateRpcClient()
				if err != nil {
					return fmt.Errorf("Failed to create RPC client: %v", err)
				}
				defer conn.Close()

				cl := pb.NewPluginClient(conn)
				if _, err := cl.Ping(ctx, &pb.PingRequest{}); err != nil {
					return fmt.Errorf("Failed to call Ping rpc: %v.\nYou may wish to run `le-cp config rpc-force-reload` and try again, which may help if your service certificate was recently changed", err)
				}
				return nil
			},
		},
		{
			"System tuning correctness",
			func() error {
				badTunings := []struct {
					Path        string
					Validator   func([]byte) bool
					Description string
				}{
					{
						"/proc/sys/net/ipv4/tcp_tw_recycle",
						func(b []byte) bool {
							return len(b) > 0 && b[0] == 0x31
						},
						"tcp_tw_recycle is NOT safe and has been removed since Linux 4.12. " +
							"You WILL experience random timeout issues if you leave this option enabled.",
					},
				}
				for _, v := range badTunings {
					buf, err := ioutil.ReadFile(v.Path)
					if os.IsNotExist(err) {
						continue
					}
					if err != nil {
						return fmt.Errorf("Could not check sysctl %s: %v", v.Path, err)
					}
					if v.Validator(buf) {
						return fmt.Errorf("Bad tuning found (%s): %s", v.Path, v.Description)
					}
				}
				return nil
			},
		},
	}

	failed := false

	for _, t := range tests {
		fmt.Print(color.WhiteString("[SELF-TEST] %s ............ ", t.Description))
		if err := t.Test(); err != nil {
			color.Red("FAILED: %s.\n", err.Error())
			failed = true
		} else {
			color.Green("SUCCESS.\n")
		}
	}

	if failed {
		color.Yellow("\nThe self-test failed. You should fix the above issues before continuing, or contact support @ https://cpanel.fleetssl.com/contact")
		color.Yellow("\nPlease first run the following command, which will send us your log files and configuration details:\n\tle-cp send-logs\n\n")
		return false
	}

	return true
}

func lockUser(u string) bool {
	muWorking.Lock()
	defer muWorking.Unlock()
	// if the lock has been open a whole hour, then forget about it
	if t, exists := working[common.NormalizeDomain(u)]; exists && time.Since(t) < time.Hour {
		return false
	}

	working[common.NormalizeDomain(u)] = time.Now()
	return true
}

func unlockUser(u string) {
	muWorking.Lock()
	defer muWorking.Unlock()
	delete(working, common.NormalizeDomain(u))
}

func makeCpanelClient(impersonate string) (cpanel.CpanelApi, error) {
	s, err := common.ReadApiToken()
	if err != nil {
		return cpanel.CpanelApi{}, err
	}

	hn, err := os.Hostname()
	if err != nil {
		return cpanel.CpanelApi{}, err
	}

	return whm.NewWhmImpersonationApiTotp(hn, "root", s, impersonate, common.ReadTotpSecret(), config.Insecure), nil
}
