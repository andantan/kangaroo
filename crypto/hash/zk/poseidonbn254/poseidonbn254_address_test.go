package poseidonbn254

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_POSEIDON_BN254_Address_BytesAndFromBytes(t *testing.T) {
	poseidonDeriver := &PoseidonBN254AddressDeriver{}
	testString := "poseidon_bn254_address"
	originalAddress := poseidonDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, hash.AddressLength, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := PoseidonBN254AddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))
}

func Test_POSEIDON_BN254_Address_IsZero(t *testing.T) {
	zeroAddr := PoseidonBN254Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, err := PoseidonBN254AddressFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroAddr.IsZero())

	poseidonDeriver := &PoseidonBN254AddressDeriver{}
	nilAddress := poseidonDeriver.Derive(nil)
	assert.True(t, nilAddress.IsZero())
}

func Test_POSEIDON_BN254_Address_Wrapper_RoundTrip(t *testing.T) {
	testString := "poseidon_bn254_address"
	testBytes := []byte(testString)
	deriver := &PoseidonBN254AddressDeriver{}
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
