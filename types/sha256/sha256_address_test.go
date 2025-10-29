package sha256

import (
	"github.com/andantan/kangaroo/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddress_BytesAndFromBytes(t *testing.T) {
	originalBytes := make([]byte, types.AddressLength)
	originalBytes[0] = 0xaa
	originalBytes[19] = 0xbb

	// FromBytes
	addr, err := SHA256AddressFromBytes(originalBytes)
	assert.NoError(t, err)

	// Bytes
	resultBytes := addr.Bytes()
	assert.Equal(t, originalBytes, resultBytes)

	_, err = SHA256AddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestAddress_IsZero(t *testing.T) {
	zeroAddr := SHA256Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, types.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, _ := SHA256AddressFromBytes(nonZeroBytes)
	assert.False(t, nonZeroAddr.IsZero())
}
