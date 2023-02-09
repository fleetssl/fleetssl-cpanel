package common

import (
	"crypto/x509"
)

func parseDERs(chain [][]byte) []*x509.Certificate {
	out := []*x509.Certificate{}
	for _, der := range chain {
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		out = append(out, crt)
	}
	return out
}
