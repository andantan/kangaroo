package ripemd160

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_RIPEMD160_Address_BytesAndFromBytes(t *testing.T) {
	ripemdDeriver := &Ripemd160AddressDeriver{}
	testString := "ripemd160_address"
	originalAddress := ripemdDeriver.Derive([]byte(testString))
	originalBytes := originalAddress.Bytes()
	assert.Equal(t, kangarooregistry.RIPEMD160AddressByte, originalBytes[0])
	assert.Equal(t, kangaroohash.AddressLength+1, len(originalBytes))

	// FromBytes
	fromAddressBytes, err := kangarooregistry.ParseAddressFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressBytes))

	_, err = kangarooregistry.ParseAddressFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_RIPEMD160_Address_StringAndFromString(t *testing.T) {
	ripemdDeriver := &Ripemd160AddressDeriver{}
	testString := "ripemd160_address"
	originalAddress := ripemdDeriver.Derive([]byte(testString))
	originalString := originalAddress.String()

	// FromString
	fromAddressString, err := kangarooregistry.ParseAddressFromString(originalString)
	require.NoError(t, err)
	assert.True(t, originalAddress.Equal(fromAddressString))

	_, err = kangarooregistry.ParseAddressFromString("0x15eaab4")
	assert.Error(t, err)
}

func Test_RIPEMD160_Address_IsZero(t *testing.T) {
	zeroAddr := Ripemd160Address{}
	assert.True(t, zeroAddr.IsZero())

	nonZeroBytes := make([]byte, kangaroohash.AddressLength)
	nonZeroBytes[10] = 0x01
	nonZeroAddr, _ := Ripemd160AddressFromBytes(nonZeroBytes)
	assert.False(t, nonZeroAddr.IsZero())
}
