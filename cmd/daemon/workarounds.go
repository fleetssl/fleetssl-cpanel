package daemon

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

func processWorkarounds() {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithError(err).Error("Failed to create fsnotify watcher for workarounds")
		return
	}

	watchPaths := []string{"/var/cpanel/ssl/installed/cabundles", "/var/cpanel/ssl/cpanel"}
	for _, p := range watchPaths {
		if err := w.Add(p); err != nil {
			log.WithError(err).WithField("path", p).Warn("Failed to watch path")
		}
	}

	defer w.Close()

	go func() {
		for {
			select {
			case evt := <-w.Events:
				if evt.Name == cabundleFilename && (evt.Op == fsnotify.Remove || evt.Op == fsnotify.Rename) {
					if err := workaroundDeletedCabundle(); err != nil {
						log.WithError(err).Warn("cabundle workaround failed")
					}
				} else if evt.Name == common.MyCpanelPEMPath {
					if err := workaroundReloadRpc(); err != nil {
						log.WithError(err).Warn("mycpanel reload workaround failed")
					}
				}
			case err := <-w.Errors:
				log.WithError(err).Warn("Watcher error")
			}
		}
	}()

	select {}
}

const (
	cabundleFilename = "/var/cpanel/ssl/installed/cabundles/Let_s_Encrypt_d5a69d0f2effae8513e08eaced2ccf28_1615999246.cabundle"
	cabundleContents = `-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----`
)

// Workaround for cPanel ticket #8829413
// We are not using fsnotify because it brings in x/sys which is huge
// 1 minute stat call should not be burdunsome whatsoever
func workaroundDeletedCabundle() error {
	if os.Getenv("WORKAROUND_DISABLE_8829413") != "" {
		return nil
	}

	_, err := os.Stat(cabundleFilename)
	if err == nil {
		return nil
	}

	log.Info("cabundle is missing, will try to re-create (8829413/ca-bundle workaround)")

	if os.IsNotExist(err) == false {
		return fmt.Errorf("stat() error unrelated to existence: %v", err)
	}

	// The file doesn't exist, we shall create it
	if err := ioutil.WriteFile(cabundleFilename, []byte(cabundleContents), 0644); err != nil {
		return fmt.Errorf("Failed to write cabundle: %v", err)
	}

	return nil
}

var (
	lastRpcReload time.Time
)

func workaroundReloadRpc() error {
	if os.Getenv("WORKAROUND_DISABLE_RPCRELOAD") != "" {
		return nil
	}

	if !lastRpcReload.IsZero() {
		if time.Now().Sub(lastRpcReload) < time.Second {
			log.Info("inhibiting rpc reload trigger because there was one very recently")
			return nil
		}
	}

	lastRpcReload = time.Now()

	log.Info("Detected mycpanel.pem changed, will try reload now")

	select {
	case rpcRestartCh <- struct{}{}:
		break
	case <-time.After(10 * time.Second):
		return errors.New("Daemon reload request timed out")
	}

	return nil
}
