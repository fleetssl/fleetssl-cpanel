package cpanelcgi

import (
	"crypto/x509"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
)

func actionView(data ActionData) ErrorList {
	domain := data.Req.FormValue("domain")

	if _, validDomain := data.DomainList[domain]; !validDomain {
		return ErrorList{TS("Invalid domain specified"), domain}
	}

	domainCert, present := data.NVData.Certs[domain]
	if !present {
		return ErrorList{TS("Domain does not have a certificate"), domain}
	}

	cert, err := common.DecodeToCert(domainCert.DomainCert)
	if err != nil {
		return ErrorList{TS("Unable to parse domain certificate"), domain}
	}

	serveTemplate(data, "view.html", struct {
		// old entries for backwards compatibility on anyone's "themes"
		Domain    string
		Subject   string
		DNSNames  []string
		Issuer    string
		NotBefore string
		NotAfter  string
		Cert      string
		Id        string
		Url       string

		// new entries
		Certificate *x509.Certificate
		NvdataCert  *common.NVDataDomainCerts
		CaBundle    string
	}{
		Domain:    domain,
		Subject:   cert.Subject.CommonName,
		DNSNames:  cert.DNSNames,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.String(),
		NotAfter:  cert.NotAfter.String(),
		Cert:      domainCert.DomainCert,
		Id:        domainCert.CertId,
		Url:       domainCert.OrderUrl,

		Certificate: cert,
		NvdataCert:  domainCert,
		CaBundle:    common.CABundle,
	})

	return nil
}
