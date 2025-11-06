package mimcbn254

import (
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_MIMC_BN254_Hash_BytesAndFromBytes(t *testing.T) {
	mimcDeriver := &MimcBN254HashDeriver{}
	testString := "mimc_bn254_hash"
	originalHash := mimcDeriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, hash.HashLength, len(originalBytes))

	// FromBytes
	fromHashBytes, err := MimcBN254HashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))
}

func Test_MIMC_BN254_Hash_IsZero(t *testing.T) {
	zeroHash := MimcBN254Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, err := MimcBN254HashFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroHash.IsZero())

	mimcDeriver := &MimcBN254HashDeriver{}
	nilHash := mimcDeriver.Derive(nil)
	assert.True(t, nilHash.IsZero())
}

func Test_MIMC_BN254_Hash_Wrapper_RoundTrip(t *testing.T) {
	testString := "mimc_bn254_hash"
	testBytes := []byte(testString)
	deriver := &MimcBN254HashDeriver{}
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
