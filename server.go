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
	"net"
	"time"
)

// MakeServerTls generates a server TLS certificate using a CA to sign it
// If ca is nil then the server will sign its own certificate
// dnsNames and ipAddresses can be nil if they are not required on the certificate
func MakeServerTls(ca *CertGen, bits int, name pkix.Name, serialNumber *big.Int, future Future, dnsNames []string, ipAddresses []net.IP) (*CertGen, error) {
	// generate rsa private key
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// generate SubjectKeyId from sha1 hash of public key bytes
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&serverPrivKey.PublicKey)
	pubKeyHash := sha1.Sum(pubKeyBytes)

	// base certificate data
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      name,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    now,
		NotAfter:     future(now),
		SubjectKeyId: pubKeyHash[:],
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// use current certificate as CA if nil
	if ca == nil {
		ca = &CertGen{cert: cert, key: serverPrivKey}
	}

	// create certificate bytes
	serverBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, serverPrivKey.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate bytes: %w", err)
	}

	// add the raw certificate bytes so `*x509.Certificate.Equal(*x509.Certificate)` is valid
	cert.Raw = serverBytes

	// get private key bytes
	privKeyBytes := x509.MarshalPKCS1PrivateKey(serverPrivKey)
	gen := &CertGen{cert: cert, certBytes: serverBytes, key: serverPrivKey, keyBytes: privKeyBytes}

	// generate pem blocks
	err = gen.generatePem()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PEM encoding: %w", err)
	}

	// generate key pair
	caKeyPair, err := tls.X509KeyPair(gen.certPem, gen.keyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key pair: %w", err)
	}

	gen.tlsCert = caKeyPair
	return gen, nil
}
