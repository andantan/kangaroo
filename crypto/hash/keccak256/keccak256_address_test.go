package keccak256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_KECCAK256_Address_BytesAndFromBytes(t *testing.T) {
	keccakDeriver := &Keccak256AddressDeriver{}
	testString := "keccak256_address"
	originalAddress := keccakDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, kangarooregistry.KECCAK256AddressByte, originalBytes[0])
	assert.Equal(t, kangaroohash.AddressLength+1, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := kangarooregistry.ParseAddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))

	_, err = kangarooregistry.ParseAddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_KECCAK256_Address_StringAndFromString(t *testing.T) {
	keccakDeriver := &Keccak256AddressDeriver{}
	testString := "keccak256_address"
	originalAddress := keccakDeriver.Derive([]byte(testString))
	originalString := originalAddress.String()

	// FromString
	fromAddressString, err := kangarooregistry.ParseAddressFromString(originalString)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressString))

	_, err = kangarooregistry.ParseAddressFromString("0x15eaab4")
	assert.Error(t, err)
}

func Test_KECCAK256_Address_IsZero(t *testing.T) {
	zeroAddr := Keccak256Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, kangaroohash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, _ := Keccak256AddressFromBytes(nonZeroBytes)
	assert.False(t, nonZeroAddr.IsZero())
}
