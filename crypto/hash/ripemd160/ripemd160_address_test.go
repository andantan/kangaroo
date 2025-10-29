package ripemd160

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_RIPEMD160_Address_BytesAndFromBytes(t *testing.T) {
	originalBytes := make([]byte, hash.AddressLength)
	originalBytes[0] = 0xaa
	originalBytes[19] = 0xbb

	// FromBytes
	addr, err := Ripemd160AddressFromBytes(originalBytes)
	assert.NoError(t, err)

	// Bytes
	resultBytes := addr.Bytes()
	assert.Equal(t, originalBytes, resultBytes)

	_, err = Ripemd160AddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_RIPEMD160_Address_IsZero(t *testing.T) {
	zeroAddr := Ripemd160Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, _ := Ripemd160AddressFromBytes(nonZeroBytes)
	assert.False(t, nonZeroAddr.IsZero())
}
