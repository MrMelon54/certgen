package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

func MakeCaTls() (*CertGen, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(29052019),
		Subject: pkix.Name{
			Organization: []string{"Ski Creds Server"},
			Country:      []string{"GB"},
			Province:     []string{""},
			Locality:     []string{"London"},
			CommonName:   "ski-creds-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln("Failed to generate CA private key:", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPrivKey.Public(), caPrivKey)
	if err != nil {
		log.Fatalln("Failed to generate CA certificate bytes:", err)
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(caPrivKey)
	gen := &CertGen{cert: ca, certBytes: caBytes, key: caPrivKey, keyBytes: privKeyBytes}
	err = gen.generatePem()
	if err != nil {
		return nil, err
	}
	caKeyPair, err := tls.X509KeyPair(gen.certPem, gen.keyPem)
	if err != nil {
		log.Fatalln("Failed to generate CA key pair:", err)
	}
	gen.tlsCert = caKeyPair
	return gen, nil
}
