package poseidonbn254

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_POSEIDON_BN254_Hash_BytesAndFromBytes(t *testing.T) {
	bn254Deriver := &PoseidonBN254HashDeriver{}
	testString := "poseidon_bn254_hash"
	originalHash := bn254Deriver.Derive([]byte(testString))
	originalBytes := originalHash.Bytes()
	assert.Equal(t, hash.HashLength, len(originalBytes))

	// FromBytes
	fromHashBytes, err := PoseidonBN254HashFromBytes(originalBytes)
	require.NoError(t, err)
	assert.True(t, originalHash.Equal(fromHashBytes))
}

func Test_POSEIDON_BN254_Hash_IsZero(t *testing.T) {
	zeroHash := PoseidonBN254Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, err := PoseidonBN254HashFromBytes(nonZeroBytes)
	require.NoError(t, err)
	assert.False(t, nonZeroHash.IsZero())
}
