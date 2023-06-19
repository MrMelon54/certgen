package certgen

import (
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

func TestMakeClientTls(t *testing.T) {
	client, err := MakeClientTls(nil, 2048, pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"certgen"},
		OrganizationalUnit: []string{"test"},
		SerialNumber:       "2",
		CommonName:         "certgen.client",
	}, big.NewInt(2), func(now time.Time) time.Time {
		return now.AddDate(10, 0, 0)
	})
	assert.NoError(t, err)
	assert.Equal(t, "certgen.client", client.cert.Subject.CommonName)
}
