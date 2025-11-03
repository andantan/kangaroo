package sha256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SHA256_Hash_BytesAndFromBytes(t *testing.T) {
	shaDeriver := &Sha256HashDeriver{}
	testString := "sha256_hash"
	originalHash := shaDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, kangarooregistry.SHA256HashPrefixByte, originalBytes[0])
	assert.Equal(t, kangaroohash.HashLength+1, len(originalBytes))

	// FromBytes
	fromHashBytes, err := kangarooregistry.ParseHashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))

	_, err = kangarooregistry.ParseHashFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_SHA256_Hash_StringAndFromString(t *testing.T) {
	shaDeriver := &Sha256HashDeriver{}
	testString := "sha256_hash"
	originalHash := shaDeriver.Derive([]byte(testString))
	originString := originalHash.String()

	// FromString
	fromHashString, err := kangarooregistry.ParseHashFromString(originString)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashString))

	_, err = kangarooregistry.ParseHashFromString("0x15eaab4")
	assert.Error(t, err)
}

func Test_SHA256_Hash_IsZero(t *testing.T) {
	zeroHash := Sha256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, kangaroohash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, _ := Sha256HashFromBytes(nonZeroBytes)
	assert.False(t, nonZeroHash.IsZero())
}
