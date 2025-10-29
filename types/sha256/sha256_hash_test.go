package sha256

import (
	"github.com/andantan/kangaroo/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash_BytesAndFromBytes(t *testing.T) {
	originalBytes := make([]byte, types.HashLength)
	originalBytes[0] = 0xde
	originalBytes[1] = 0xad
	originalBytes[31] = 0xef

	// FromBytes
	hash, err := SHA256HashFromBytes(originalBytes)
	assert.NoError(t, err)

	// Bytes
	resultBytes := hash.Bytes()
	assert.Equal(t, originalBytes, resultBytes)

	_, err = SHA256HashFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestHash_StringAndFromHexString(t *testing.T) {
	originalStr := "deadbeef000000000000000000000000000000000000000000000000beefdead"

	// FromHexString
	hash, err := SHA256HashFromString(originalStr)
	assert.NoError(t, err)

	// String
	resultStr := hash.String()
	assert.Equal(t, "0x"+originalStr, resultStr)

	// FromHexString
	hashWithPrefix, err := SHA256HashFromString("0x" + originalStr)
	assert.NoError(t, err)
	assert.Equal(t, hash, hashWithPrefix)

	_, err = SHA256HashFromString("123456")
	assert.Error(t, err)

	_, err = SHA256HashFromString("gg")
	assert.Error(t, err)
}

func TestHash_IsZero(t *testing.T) {
	zeroHash := SHA256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, types.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, _ := SHA256HashFromBytes(nonZeroBytes)
	assert.False(t, nonZeroHash.IsZero())
}
