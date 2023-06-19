package certgen

import (
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestMakeCaTls(t *testing.T) {
	ca, err := MakeCaTls(2048, pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"certgen"},
		OrganizationalUnit: []string{"test"},
		SerialNumber:       "1",
		CommonName:         "certgen.test",
	}, big.NewInt(1))
	assert.NoError(t, err)
	assert.Equal(t, "certgen.test", ca.cert.Subject.CommonName)
}
