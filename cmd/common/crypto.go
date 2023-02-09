package common

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"
)

type Pk interface {
	AsPEM() string
	Unwrapped() interface{}
}

type PkRSA struct {
	*rsa.PrivateKey
}

func (k PkRSA) AsPEM() string {
	buf := x509.MarshalPKCS1PrivateKey(k.PrivateKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: buf}))
}

func (k PkRSA) Unwrapped() interface{} {
	return k.PrivateKey
}

type PkECDSA struct {
	*ecdsa.PrivateKey
}

func (k PkECDSA) AsPEM() string {
	buf, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		panic("Failed to marshal ec key: " + err.Error())
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: buf}))
}

func (k PkECDSA) Unwrapped() interface{} {
	return k.PrivateKey
}

// this function is used to either create a new key or use the existing key
type PrivateKeyFunc func() (Pk, error)

func PrivateKeyError(err error) PrivateKeyFunc {
	return func() (Pk, error) { return nil, err }
}

func PrivateKeyFromPem(s string) PrivateKeyFunc {
	dBlock, _ := pem.Decode([]byte(s))
	if dBlock == nil {
		return PrivateKeyError(errors.New("Failed to decode private key"))
	}

	switch dBlock.Type {
	case "RSA PRIVATE KEY":
		pk, err := x509.ParsePKCS1PrivateKey(dBlock.Bytes)
		return func() (Pk, error) { return PkRSA{pk}, err }
	case "EC PRIVATE KEY":
		pk, err := x509.ParseECPrivateKey(dBlock.Bytes)
		return func() (Pk, error) { return PkECDSA{pk}, err }
	default:
		return func() (Pk, error) { return nil, fmt.Errorf("Unkown key header: %v", dBlock.Type) }
	}
}

// it's a new certificate so generate a new domain private key
func DefaultPrivateKey(params client.CryptoParams) (Pk, error) {
	switch params.Type {
	case client.KeyTypeRSA:
		start := time.Now()
		k, err := rsa.GenerateKey(rand.Reader, params.RsaKeySize)
		log.WithField("duration", time.Now().Sub(start)).Println("Generated RSA key")
		return PkRSA{k}, err
	case client.KeyTypeECDSA:
		start := time.Now()
		k, err := ecdsa.GenerateKey(params.Curve, rand.Reader)
		log.WithField("duration", time.Now().Sub(start)).Println("Generated ECDSA key")
		return PkECDSA{k}, err
	default:
		return nil, fmt.Errorf("Unknown key type: %v", params.Type)
	}
}

func DefaultPrivateKeyFunc(params client.CryptoParams) PrivateKeyFunc {
	return func() (Pk, error) { return DefaultPrivateKey(params) }
}

// First domain is the prmary domain, rest are SANs
func newCSR(domains []string, pk Pk) (*x509.CertificateRequest, error) {

	var publicKey interface{}
	var privateKey interface{}
	var sigAlg x509.SignatureAlgorithm
	var pkAlg x509.PublicKeyAlgorithm

	if pk, ok := pk.(PkRSA); ok {
		publicKey = pk.PublicKey
		privateKey = pk.PrivateKey
		sigAlg = x509.SHA256WithRSA
		pkAlg = x509.RSA
	}
	if pk, ok := pk.(PkECDSA); ok {
		publicKey = pk.PublicKey
		privateKey = pk.PrivateKey
		sigAlg = x509.ECDSAWithSHA256
		pkAlg = x509.ECDSA
	}

	if publicKey == nil || privateKey == nil {
		return nil, fmt.Errorf("Unknown private key type: %v", reflect.TypeOf(pk))
	}

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: sigAlg,
		PublicKeyAlgorithm: pkAlg,
		PublicKey:          publicKey,
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           []string{domains[0]},
	}

	if len(domains) > 1 {
		tpl.DNSNames = append(tpl.DNSNames, domains[1:]...)
	}

	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, privateKey)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func EncodeToPEM(keyType string, keyData []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyData}))
}

func DecodeToCert(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("Unable to decode pem")
	}

	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func PEMToCertificateSlice(asPEM string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var lastErr error

	body := []byte(asPEM)
	for {
		var p *pem.Block
		p, body = pem.Decode(body)
		if p == nil {
			break
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			lastErr = err
			break
		}
		certs = append(certs, cert)
	}

	return certs, lastErr
}

func CertificateSliceToPEMSlice(certs []*x509.Certificate) []string {
	var pems []string
	for _, cert := range certs {
		pems = append(pems, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
	}
	return pems
}
