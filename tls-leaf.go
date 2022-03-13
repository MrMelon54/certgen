package certgen

import (
	"crypto/tls"
	"crypto/x509"
)

func TlsLeaf(cert *tls.Certificate) *x509.Certificate {
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) >= 1 {
		if a, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cert.Leaf = a
		}
	}
	return cert.Leaf
}
