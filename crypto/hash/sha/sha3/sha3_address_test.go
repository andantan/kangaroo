package sha3

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_SHA3_Address_BytesAndFromBytes(t *testing.T) {
	shaDeriver := &Sha3AddressDeriver{}
	testString := "sha3_address"
	originalAddress := shaDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, hash.AddressLength, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := Sha3AddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))
}

func Test_SHA3_Address_IsZero(t *testing.T) {
	zeroAddr := Sha3Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, err := Sha3AddressFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroAddr.IsZero())

	shaDeriver := &Sha3AddressDeriver{}
	nilAddress := shaDeriver.Derive(nil)
	assert.True(t, nilAddress.IsZero())
}

func Test_SHA3_Address_Wrapper_RoundTrip(t *testing.T) {
	testString := "sha3_address"
	testBytes := []byte(testString)
	deriver := &Sha3AddressDeriver{}
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
