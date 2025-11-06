package blake2b256

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_BLAKE2B256_Hash_BytesAndFromBytes(t *testing.T) {
	blakeDeriver := &Blake2b256HashDeriver{}
	testString := "blake2b256_hash"
	originalHash := blakeDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, hash.HashLength, len(originalBytes))

	// FromBytes
	fromHashBytes, err := Blake2b256HashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))
}

func Test_BLAKE2B256_Hash_IsZero(t *testing.T) {
	zeroHash := Blake2b256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, err := Blake2b256HashFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroHash.IsZero())

	blakeDeriver := &Blake2b256HashDeriver{}
	nilHash := blakeDeriver.Derive(nil)
	assert.True(t, nilHash.IsZero())
}

func Test_BLAKE2B256_Hash_Wrapper_RoundTrip(t *testing.T) {
	testString := "blake2b256_hash"
	testBytes := []byte(testString)
	deriver := &Blake2b256HashDeriver{}
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
