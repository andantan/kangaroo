package sha256

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_SHA256_Hash_BytesAndFromBytes(t *testing.T) {
	shaDeriver := &Sha256HashDeriver{}
	testString := "sha256_hash"
	originalHash := shaDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, hash.HashLength, len(originalBytes))

	// FromBytes
	fromHashBytes, err := Sha256HashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))
}

func Test_SHA256_Hash_IsZero(t *testing.T) {
	zeroHash := Sha256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, err := Sha256HashFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroHash.IsZero())

	shaDeriver := &Sha256HashDeriver{}
	nilHash := shaDeriver.Derive(nil)
	assert.True(t, nilHash.IsZero())
}

func Test_SHA256_Hash_Wrapper_RoundTrip(t *testing.T) {
	testString := "sha256_hash"
	testBytes := []byte(testString)
	deriver := &Sha256HashDeriver{}
	h := deriver.Derive(testBytes)

	wrappedHash, err := wrapper.WrapHash(h)
	require.NoError(t, err)
	unwrappedHash, err := wrapper.UnwrapHash(wrappedHash)
	require.NoError(t, err)
	assert.True(t, h.Equal(unwrappedHash))

	wrappedHashString, err := wrapper.WrapHashToString(h)
	require.NoError(t, err)
	parsedAddr, err := wrapper.UnwrapHashFromString(wrappedHashString)
	require.NoError(t, err)
	assert.True(t, h.Equal(parsedAddr))
}
