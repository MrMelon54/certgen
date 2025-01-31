package certgen

import (
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

func TestMakeCaTls(t *testing.T) {
	ca, err := MakeCaTls(2048, pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"certgen"},
		OrganizationalUnit: []string{"test"},
		SerialNumber:       "1",
		CommonName:         "certgen.test",
	}, big.NewInt(1), func(now time.Time) time.Time {
		return now.Add(5 * time.Second)
	})
	assert.NoError(t, err)
	assert.Equal(t, "certgen.test", ca.cert.Subject.CommonName)
}
