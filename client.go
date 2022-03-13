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

func MakeClientTls() (*CertGen, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(29052019),
		Subject: pkix.Name{
			Organization: []string{"Ski Creds Client"},
			Country:      []string{"GB"},
			Province:     []string{""},
			Locality:     []string{"London"},
			CommonName:   "ski-creds-client",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln("Failed to generate client private key:", err)
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, clientPrivKey.Public(), clientPrivKey)
	if err != nil {
		log.Fatalln("Failed to generate client certificate bytes:", err)
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(clientPrivKey)
	gen := &CertGen{cert: cert, certBytes: clientBytes, key: clientPrivKey, keyBytes: privKeyBytes}
	err = gen.generatePem()
	if err != nil {
		return nil, err
	}
	caKeyPair, err := tls.X509KeyPair(gen.certPem, gen.keyPem)
	if err != nil {
		log.Fatalln("Failed to generate client key pair:", err)
	}
	gen.tlsCert = caKeyPair
	return gen, nil
}
