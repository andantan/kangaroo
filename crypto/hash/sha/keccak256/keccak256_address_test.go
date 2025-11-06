package keccak256

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_KECCAK256_Address_BytesAndFromBytes(t *testing.T) {
	keccakDeriver := &Keccak256AddressDeriver{}
	testString := "keccak256_address"
	originalAddress := keccakDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, hash.AddressLength, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := Keccak256AddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))
}

func Test_KECCAK256_Address_IsZero(t *testing.T) {
	zeroAddr := Keccak256Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, err := Keccak256AddressFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroAddr.IsZero())

	keccakDeriver := &Keccak256AddressDeriver{}
	nilAddress := keccakDeriver.Derive(nil)
	assert.True(t, nilAddress.IsZero())
}

func Test_KECCAK256_Address_Wrapper_RoundTrip(t *testing.T) {
	testString := "keccak256_address"
	testBytes := []byte(testString)
	deriver := &Keccak256AddressDeriver{}
	a := deriver.Derive(testBytes)

	wrappedAddr, err := wrapper.WrapAddress(a)
	require.NoError(t, err)
	unwrappedAddr, err := wrapper.UnwrapAddress(wrappedAddr)
	require.NoError(t, err)
	assert.True(t, a.Equal(unwrappedAddr))

	wrappedAddrString, err := wrapper.WrapAddressToString(a)
	require.NoError(t, err)
	parsedAddr, err := wrapper.UnwrapAddressFromString(wrappedAddrString)
	require.NoError(t, err)
	assert.True(t, a.Equal(parsedAddr))
}
