package keccak256

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_KECCAK256_Hash_BytesAndFromBytes(t *testing.T) {
	keccakDeriver := &Keccak256HashDeriver{}
	testString := "keccak256_hash"
	originalHash := keccakDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, hash.HashLength, len(originalBytes))

	// FromBytes
	fromHashBytes, err := Keccak256HashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))
}

func Test_KECCAK256_Hash_IsZero(t *testing.T) {
	zeroHash := Keccak256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, err := Keccak256HashFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroHash.IsZero())

	keccakDeriver := &Keccak256HashDeriver{}
	nilHash := keccakDeriver.Derive(nil)
	assert.True(t, nilHash.IsZero())
}

func Test_KECCAK256_Hash_Wrapper_RoundTrip(t *testing.T) {
	testString := "keccak256_hash"
	testBytes := []byte(testString)
	deriver := &Keccak256HashDeriver{}
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
