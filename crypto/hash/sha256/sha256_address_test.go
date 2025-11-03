package sha256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SHA256_Address_BytesAndFromBytes(t *testing.T) {
	shaDeriver := &Sha256AddressDeriver{}
	testString := "sha256_address"
	originalAddress := shaDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, kangarooregistry.SHA256AddressPrefixByte, originalBytes[0])
	assert.Equal(t, kangaroohash.AddressLength+1, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := kangarooregistry.ParseAddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))

	_, err = kangarooregistry.ParseAddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_SHA256_Address_StringAndFromString(t *testing.T) {
	shaDeriver := &Sha256AddressDeriver{}
	testString := "sha256_address"
	originalAddress := shaDeriver.Derive([]byte(testString))
	originalString := originalAddress.String()

	// FromString
	fromAddressString, err := kangarooregistry.ParseAddressFromString(originalString)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressString))

	_, err = kangarooregistry.ParseAddressFromString("0x15eaab4")
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
