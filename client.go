package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// MakeClientTls generates a client TLS certificate using a CA to sign it
// If ca is nil then the client will sign its own certificate
func MakeClientTls(ca *CertGen, bits int, name pkix.Name, serialNumber *big.Int, future Future) (*CertGen, error) {
	// generate rsa private key
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %w", err)
	}

	// generate SubjectKeyId from sha1 hash of public key bytes
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&clientPrivKey.PublicKey)
	pubKeyHash := sha1.Sum(pubKeyBytes)

	// base certificate data
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      name,
		NotBefore:    now,
		NotAfter:     future(now),
		SubjectKeyId: pubKeyHash[:],
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// use current certificate as CA if nil
	if ca == nil {
		ca = &CertGen{cert: cert, key: clientPrivKey}
	}

	// create certificate bytes
	clientBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, clientPrivKey.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client certificate bytes: %w", err)
	}

	// add the raw certificate bytes so `*x509.Certificate.Equal(*x509.Certificate)` is valid
	cert.Raw = clientBytes

	// get private key bytes
	privKeyBytes := x509.MarshalPKCS1PrivateKey(clientPrivKey)
	gen := &CertGen{cert: cert, certBytes: clientBytes, key: clientPrivKey, keyBytes: privKeyBytes}

	// generate pem blocks
	err = gen.generatePem()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PEM encoding: %w", err)
	}

	// generate key pair
	caKeyPair, err := tls.X509KeyPair(gen.certPem, gen.keyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key pair: %w", err)
	}

	gen.tlsCert = caKeyPair
	return gen, nil
}
