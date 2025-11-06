package sha3

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_SHA3_Hash_BytesAndFromBytes(t *testing.T) {
	shaDeriver := &Sha3HashDeriver{}
	testString := "sha3_hash"
	originalHash := shaDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, hash.HashLength, len(originalBytes))

	// FromBytes
	fromHashBytes, err := Sha3HashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))
}

func Test_SHA3_Hash_IsZero(t *testing.T) {
	zeroHash := Sha3Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, err := Sha3HashFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroHash.IsZero())

	shaDeriver := &Sha3HashDeriver{}
	nilHash := shaDeriver.Derive(nil)
	assert.True(t, nilHash.IsZero())
}
