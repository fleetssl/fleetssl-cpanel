package common

import (
	"fmt"
	"os/exec"
	"time"

	"io/ioutil"

	"encoding/json"

	"errors"

	"github.com/letsencrypt-cpanel/cpanelgo/whm"
	log "github.com/sirupsen/logrus"
)

const (
	pathApiToken   = "/etc/.letsencrypt-cpanel-api-token"
	pathAccessHash = "/root/.accesshash"
	pathWhmapi1    = "/usr/local/cpanel/bin/whmapi1"
)

var (
	apiTokenFailing = false
)

// attempts to read the access hash if it exists
// if it doesn't, attempt to read existing token file
// if no token file, create one and use that
func ReadApiToken() (string, error) {
	if !apiTokenFailing {
		token, err := getOrCreateApiToken()
		if err == nil {
			return token, nil
		}
		log.WithError(err).Error("getting/creating api token, attempting to fall back to accesshash")
		apiTokenFailing = true
	}

	if FileExists(pathAccessHash) {
		t, err := readFile(pathAccessHash)
		if err == nil {
			if t != "" {
				return t, nil
			}
			log.Error("access hash empty")
		} else {
			log.WithError(err).Error("reading access hash")
		}
	}

	return "", errors.New("No cPanel API authentication token available.")
}

func getOrCreateApiToken() (string, error) {
	if !FileExists(pathApiToken) {
		err := createApiToken()
		if err != nil {
			return "", err
		}
		if !FileExists(pathApiToken) {
			return "", errors.New("Unknown error creating new api token")
		}
	}

	return readFile(pathApiToken)
}

func readFile(path string) (string, error) {
	ahBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("Error reading api token file %s, %v", path, err)
	}
	if len(ahBytes) == 0 {
		return "", fmt.Errorf("Api token file %s is empty!", path)
	}

	return string(ahBytes), nil
}

func getTokenName() string {
	return fmt.Sprintf("letsencrypt-cpanel-autogen_%s", time.Now().Format("2006-01-02_15-04-05"))
}

func createApiToken() error {
	result := struct {
		whm.BaseWhmApiResponse
		// {"name":"dingus2","token":"VTEY8X9DAUVS3C1P6DD4Z6Y3EMAZ59RZ","create_time":1500269524}}
		Data struct {
			Name       string `json:"name"`
			Token      string `json:"token"`
			CreateTime int    `json:"create_time"`
		} `json:"data"`
	}{}

	tn := getTokenName()

	log.WithField("token_name", tn).Info("Creating new api token")

	out, err := exec.Command(pathWhmapi1, "--output=json", "api_token_create", fmt.Sprintf("token_name=%s", tn)).Output()
	if err != nil {
		return fmt.Errorf("Error calling new api token command: %v", err)
	}

	if err := json.Unmarshal(out, &result); err != nil {
		return fmt.Errorf("Error parsing create token output: %v", err)
	}

	if err := result.Error(); err != nil {
		return fmt.Errorf("Error creating new api token: %v", err)
	}

	if err := ioutil.WriteFile(pathApiToken, []byte(result.Data.Token), ConfigPermissions); err != nil {
		return fmt.Errorf("Error saving new api token: %v", err)
	}

	return nil
}
