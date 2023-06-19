package certgen

import (
	"crypto/tls"
	"crypto/x509"
)

func TlsLeaf(cert *tls.Certificate) *x509.Certificate {
	// return the existing leaf
	if cert.Leaf != nil {
		return cert.Leaf
	}

	if len(cert.Certificate) >= 1 {
		// if there is a certificate then validate, parse and set the leaf
		if a, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cert.Leaf = a
		}
	}
	return cert.Leaf
}
