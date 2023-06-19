package certgen

import (
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestMakeServerTls(t *testing.T) {
	server, err := MakeServerTls(nil, 2048, pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"certgen"},
		OrganizationalUnit: []string{"test"},
		SerialNumber:       "2",
		CommonName:         "certgen.server",
	}, big.NewInt(2), func(now time.Time) time.Time {
		return now.AddDate(10, 0, 0)
	}, []string{"certgen.server", "*.certgen.server"}, []net.IP{net.IPv4(1, 1, 1, 1), net.IPv6loopback})
	assert.NoError(t, err)
	assert.Equal(t, "certgen.server", server.cert.Subject.CommonName)
	assert.Equal(t, []string{"certgen.server", "*.certgen.server"}, server.cert.DNSNames)
}
