package common

import (
	"io/ioutil"
	"os"

	"encoding/json"

	"github.com/letsencrypt-cpanel/cpanelgo/whm"
)

func MakeWhmClient(insecure bool) (whm.WhmApi, error) {
	s, err := ReadApiToken()
	if err != nil {
		return whm.WhmApi{}, err
	}

	hn, err := os.Hostname()
	if err != nil {
		return whm.WhmApi{}, err
	}

	return whm.NewWhmApiAccessHashTotp(hn, "root", s, insecure, ReadTotpSecret()), nil
}

func ReadTotpSecret() string {
	totpBytes, err := ioutil.ReadFile("/var/cpanel/authn/twofactor_auth/tfa_userdata.json")
	if err != nil {
		return ""
	}

	var totpMap map[string]map[string]string

	err = json.Unmarshal(totpBytes, &totpMap)
	if err != nil {
		return ""
	}

	root, ok := totpMap["root"]
	if !ok {
		return ""
	}

	secret, ok := root["secret"]
	if !ok {
		return ""
	}

	return secret
}
