package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// MakeCaTls generates a CA TLS certificate
func MakeCaTls(bits int, name pkix.Name, serialNumber *big.Int, future Future) (*CertGen, error) {
	// base certificate data
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               name,
		NotBefore:             now,
		NotAfter:              future(now),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate rsa private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate CA private key: %w", err)
	}

	// create certificate bytes
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPrivKey.Public(), caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate CA certificate bytes: %w", err)
	}

	// add the raw certificate bytes so `*x509.Certificate.Equal(*x509.Certificate)` is valid
	ca.Raw = caBytes

	// get private key bytes
	privKeyBytes := x509.MarshalPKCS1PrivateKey(caPrivKey)
	gen := &CertGen{cert: ca, certBytes: caBytes, key: caPrivKey, keyBytes: privKeyBytes}

	// generate pem blocks
	err = gen.generatePem()
	if err != nil {
		return nil, fmt.Errorf("Failed to generate PEM encoding: %w", err)
	}

	// generate key pair
	caKeyPair, err := tls.X509KeyPair(gen.certPem, gen.keyPem)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate CA key pair: %w", err)
	}

	gen.tlsCert = caKeyPair
	return gen, nil
}
