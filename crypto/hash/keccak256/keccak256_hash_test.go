package keccak256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_KECCAK256_Hash_BytesAndFromBytes(t *testing.T) {
	keccakDeriver := &Keccak256HashDeriver{}
	testString := "keccak256_hash"
	originalHash := keccakDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, kangarooregistry.KECCAK256HashByte, originalBytes[0])
	assert.Equal(t, kangaroohash.HashLength+1, len(originalBytes))

	// FromBytes
	fromHashBytes, err := kangarooregistry.ParseHashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))

	_, err = kangarooregistry.ParseHashFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_KECCAK256_Hash_StringAndFromString(t *testing.T) {
	keccakDeriver := &Keccak256HashDeriver{}
	testString := "keccak256_hash"
	originalHash := keccakDeriver.Derive([]byte(testString))
	originString := originalHash.String()

	// FromString
	fromHashString, err := kangarooregistry.ParseHashFromString(originString)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashString))

	_, err = kangarooregistry.ParseHashFromString("0x15eaab4")
	assert.Error(t, err)
}

func Test_KECCAK256_Hash_IsZero(t *testing.T) {
	zeroHash := Keccak256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, kangaroohash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, _ := Keccak256HashFromBytes(nonZeroBytes)
	assert.False(t, nonZeroHash.IsZero())
}
