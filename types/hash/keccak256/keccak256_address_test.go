package keccak256

import (
	"github.com/andantan/kangaroo/types/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_KECCAK256_Address_BytesAndFromBytes(t *testing.T) {
	originalBytes := make([]byte, hash.AddressLength)
	originalBytes[0] = 0xaa
	originalBytes[19] = 0xbb

	// FromBytes
	addr, err := Keccak256AddressFromBytes(originalBytes)
	assert.NoError(t, err)

	// Bytes
	resultBytes := addr.Bytes()
	assert.Equal(t, originalBytes, resultBytes)

	_, err = Keccak256AddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_KECCAK256_Address_IsZero(t *testing.T) {
	zeroAddr := Keccak256Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, _ := Keccak256AddressFromBytes(nonZeroBytes)
	assert.False(t, nonZeroAddr.IsZero())
}
