package certgen

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
)

type CertGen struct {
	tlsCert             tls.Certificate
	cert                *x509.Certificate
	key                 crypto.PrivateKey
	certBytes, keyBytes []byte
	certPem, keyPem     []byte
}

func (ca *CertGen) GetTlsLeaf() tls.Certificate {
	return ca.tlsCert
}

func (ca *CertGen) generatePem() error {
	a := new(bytes.Buffer)
	b := new(bytes.Buffer)
	err := pem.Encode(a, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.certBytes,
	})
	if err != nil {
		return err
	}
	err = pem.Encode(b, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: ca.keyBytes,
	})
	if err != nil {
		return err
	}
	ca.certPem = a.Bytes()
	ca.keyPem = b.Bytes()
	return nil
}

func (ca *CertGen) SaveFiles(caCert, caKey io.Writer) error {
	_, err := caCert.Write(ca.certPem)
	if err != nil {
		return err
	}
	_, err = caKey.Write(ca.keyPem)
	return err
}

func LoadCertGen(certBytes, keyBytes []byte) (*CertGen, error) {
	pair, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	leaf := TlsLeaf(&pair)
	return &CertGen{
		tlsCert:   pair,
		cert:      leaf,
		key:       pair.PrivateKey,
		certBytes: certBytes,
		keyBytes:  keyBytes,
	}, nil
}
