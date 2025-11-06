package mimcbn254

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_MIMC_BN254_Address_BytesAndFromBytes(t *testing.T) {
	mimcDeriver := &MimcBN254AddressDeriver{}
	testString := "mimc_bn254_address"
	originalAddress := mimcDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, hash.AddressLength, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := MimcBN254AddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))
}

func Test_MIMC_BN254_Address_IsZero(t *testing.T) {
	zeroAddr := MimcBN254Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, hash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, err := MimcBN254AddressFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroAddr.IsZero())

	mimcDeriver := &MimcBN254AddressDeriver{}
	nilAddr := mimcDeriver.Derive(nil)
	assert.True(t, nilAddr.IsZero())
}
