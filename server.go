package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"time"
)

func MakeServerTls(ca *CertGen, name pkix.Name, serialNumber *big.Int, dnsNames []string, ipAddresses []net.IP) (*CertGen, error) {
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      name,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln("Failed to generate server private key:", err)
	}

	if ca == nil {
		ca = &CertGen{cert: cert, key: serverPrivKey}
	}
	serverBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, serverPrivKey.Public(), ca.key)
	if err != nil {
		log.Fatalln("Failed to generate server certificate bytes:", err)
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(serverPrivKey)
	gen := &CertGen{cert: cert, certBytes: serverBytes, key: serverPrivKey, keyBytes: privKeyBytes}
	err = gen.generatePem()
	if err != nil {
		return nil, err
	}
	caKeyPair, err := tls.X509KeyPair(gen.certPem, gen.keyPem)
	if err != nil {
		log.Fatalln("Failed to generate server key pair:", err)
	}
	gen.tlsCert = caKeyPair
	return gen, nil
}
