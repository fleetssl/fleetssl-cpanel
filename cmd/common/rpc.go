package common

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func CreateRpcClient() (*grpc.ClientConn, context.Context, error) {
	opts := []grpc.DialOption{}
	if useTls, crt, _ := GetTLSForRPC(); useTls {
		cp := x509.NewCertPool()
		cp.AddCert(crt)
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:            cp,
			InsecureSkipVerify: os.Getenv("FLEETSSL_INSECURE_RPC") == "y",
		})))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	hn, _ := os.Hostname()
	conn, err := grpc.Dial(fmt.Sprintf("%s:5960", hn), opts...)
	if err != nil {
		return nil, nil, err
	}

	sBuf, err := ReadApiToken()
	if err != nil {
		return nil, nil, err
	}

	sBuf = strings.Replace(sBuf, "\n", "", -1)
	sBuf = strings.TrimSpace(strings.Replace(sBuf, "\r", "", -1))

	clCtx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("accesshash", base64.StdEncoding.EncodeToString([]byte(sBuf))))

	return conn, clCtx, nil

}

// Pretty much, only use mycpanel.pem
const MyCpanelPEMPath = "/var/cpanel/ssl/cpanel/mycpanel.pem"

func GetTLSForRPC() (bool, *x509.Certificate, tls.Certificate) {
	var crtBuf []byte

	if _, err := os.Stat(MyCpanelPEMPath); err == nil {
		bb, err := ioutil.ReadFile(MyCpanelPEMPath)
		if err != nil {
			log.WithError(err).Error("Failed to read mycpanel.pem")
			return false, nil, tls.Certificate{}
		}
		crtBuf = bb
	}

	// check certificate validates
	hn, _ := os.Hostname()

	var crt *x509.Certificate
	for crt == nil && len(crtBuf) > 0 {
		block, rest := pem.Decode(crtBuf)
		crtBuf = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		if _, err := c.Verify(x509.VerifyOptions{
			DNSName: hn,
		}); err != nil {
			continue
		}

		crt = c
		break
	}

	if crt == nil {
		//log.Printf("Failed to find a certificate that validates for %s", hn)
		return false, nil, tls.Certificate{}
	}

	tlsCrt, err := tls.LoadX509KeyPair(MyCpanelPEMPath, MyCpanelPEMPath)
	if err != nil {
		log.WithError(err).Printf("Failed to parse tls certificate")
		return false, nil, tls.Certificate{}
	}

	return true, crt, tlsCrt
}
