package ripemd160

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_RIPEMD160_Address_BytesAndFromBytes(t *testing.T) {
	ripemdDeriver := &Ripemd160AddressDeriver{}
	testString := "ripemd160_address"
	originalAddress := ripemdDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, hash.AddressLength, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := Ripemd160AddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))
}

func Test_RIPEMD160_Address_IsZero(t *testing.T) {
	zeroAddr := Ripemd160Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, err := Ripemd160AddressFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroAddr.IsZero())

	ripemdDeriver := &Ripemd160AddressDeriver{}
	nilAddress := ripemdDeriver.Derive(nil)
	assert.True(t, nilAddress.IsZero())
}
