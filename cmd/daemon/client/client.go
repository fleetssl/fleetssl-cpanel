package client

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func GetConfig(config string) (string, error) {
	v := url.Values{
		"config": []string{config},
	}
	resp, err := http.PostForm("http://127.0.0.1:5959/cgi-config", v)
	if err != nil {
		log.WithError(err).WithField("Config", config).Error("Failed to get cgi check config")
		return "", fmt.Errorf("Failed to check cgi config %s: %v", config, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.WithField("Response", resp).WithField("Config", config).Error("Failed to get cgi check config")
		return "", fmt.Errorf("Error checking cgi config: %v", resp)
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).WithField("Config", config).Error("Failed to get cgi check config")
		return "", fmt.Errorf("Error reading cgi config response: %v", resp)
	}

	return string(contents), nil
}

type CryptoParams struct {
	Type       KeyType
	RsaKeySize int
	Curve      elliptic.Curve
}

func (c *CryptoParams) String() string {
	if c.Type == KeyTypeECDSA {
		return strings.ToLower(fmt.Sprintf("ecdsa:%s", c.Curve.Params().Name))
	} else if c.Type == KeyTypeRSA {
		return fmt.Sprintf("rsa:%d", c.RsaKeySize)
	}
	return "invalid"
}

func KeyTypeStringToParams(s string) (CryptoParams, error) {
	var params CryptoParams
	split := strings.Split(s, ":")
	if len(split) != 2 {
		return params, errors.New("Invalid input")
	}

	if split[0] == "rsa" {
		size, err := strconv.ParseInt(split[1], 10, 64)
		if err != nil {
			return params, err
		}
		params.RsaKeySize = int(size)
		params.Type = KeyTypeRSA
		return params, nil
	} else if split[0] == "ecdsa" {
		params.Type = KeyTypeECDSA
		switch split[1] {
		case "p-256":
			params.Curve = elliptic.P256()
		case "p-384":
			params.Curve = elliptic.P384()
		default:
			return params, errors.New("Invalid ECDSA curve")
		}
		return params, nil
	}
	return params, errors.New("Invalid key type")
}

type KeyType string

var (
	KeyTypeRSA   KeyType = "rsa"
	KeyTypeECDSA KeyType = "ecdsa"
)

func GetCryptoParams() CryptoParams {
	defaultParams := CryptoParams{
		Type:       KeyTypeECDSA,
		RsaKeySize: 2048,
		Curve:      elliptic.P256(),
	}

	kt, err := GetConfig("crypto_params")
	if err != nil {
		log.WithError(err).Error("Failed to fetch crypto params")
		return defaultParams
	}

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(kt), &out); err != nil {
		log.WithError(err).Error("Failed to decode crypto params")
		return defaultParams
	}

	switch out["Alg"] {
	case "rsa":
		defaultParams.Type = KeyTypeRSA
	case "ecdsa":
		defaultParams.Type = KeyTypeECDSA
	}

	size, ok := out["RsaKeySize"].(float64)
	if !ok {
		log.WithField("Params", out).Warn("Invalid key size")
		size = float64(defaultParams.RsaKeySize)
	}
	defaultParams.RsaKeySize = int(math.Min(float64(4096), math.Max(float64(2048), size)))

	switch out["EcdsaCurve"] {
	case "p-256":
		defaultParams.Curve = elliptic.P256()
	case "p-384":
		defaultParams.Curve = elliptic.P384()
	}

	return defaultParams
}

func GetChallengeMethods() ([]string, error) {
	s, err := GetConfig("challenge_methods")
	if err != nil {
		return nil, err
	}

	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}

	return out, nil
}

func GetDNSChallengeDelay() (int, error) {
	s, err := GetConfig("dns_challenge_delay_secs")
	if err != nil {
		return 5, err
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return 5, err
	}
	return i, nil
}

func GetAutocheckedPrefixes() ([]string, error) {
	s, err := GetConfig("ui_autochecked_prefixes")
	if err != nil {
		return []string{}, err
	}
	return strings.Split(s, ","), nil
}

func GetPreferredIssuer() (string, error) {
	return GetConfig("preferred_issuer_cn")
}
