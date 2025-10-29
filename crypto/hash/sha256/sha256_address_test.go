package sha256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SHA256_Address_BytesAndFromBytes(t *testing.T) {
	originalBytes := make([]byte, kangaroohash.AddressLength)
	originalBytes[0] = 0xaa
	originalBytes[19] = 0xbb

	// FromBytes
	addr, err := Sha256AddressFromBytes(originalBytes)
	assert.NoError(t, err)

	// Bytes
	resultBytes := addr.Bytes()
	assert.Equal(t, originalBytes, resultBytes)

	_, err = Sha256AddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_SHA256_Address_IsZero(t *testing.T) {
	zeroAddr := Sha256Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, kangaroohash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, _ := Sha256AddressFromBytes(nonZeroBytes)
	assert.False(t, nonZeroAddr.IsZero())
}
