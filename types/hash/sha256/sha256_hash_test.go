package sha256

import (
	"github.com/andantan/kangaroo/types/hash"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SHA256_Hash_BytesAndFromBytes(t *testing.T) {
	originalBytes := make([]byte, hash.HashLength)
	originalBytes[0] = 0xde
	originalBytes[1] = 0xad
	originalBytes[31] = 0xef

	// FromBytes
	h, err := Sha256HashFromBytes(originalBytes)
	assert.NoError(t, err)

	// Bytes
	resultBytes := h.Bytes()
	assert.Equal(t, originalBytes, resultBytes)

	_, err = Sha256HashFromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_SHA256_Hash_StringAndFromString(t *testing.T) {
	originalStr := "deadbeef000000000000000000000000000000000000000000000000beefdead"

	// FromHexString
	h, err := Sha256HashFromString(originalStr)
	assert.NoError(t, err)

	// String
	resultStr := h.String()
	assert.Equal(t, "0x"+originalStr, resultStr)

	// FromHexString
	hashWithPrefix, err := Sha256HashFromString("0x" + originalStr)
	assert.NoError(t, err)
	assert.Equal(t, h, hashWithPrefix)

	_, err = Sha256HashFromString("123456")
	assert.Error(t, err)

	_, err = Sha256HashFromString("gg")
	assert.Error(t, err)
}

func Test_SHA256_Hash_IsZero(t *testing.T) {
	zeroHash := Sha256Hash{}
	assert.True(t, zeroHash.IsZero())

	nonZeroBytes := make([]byte, hash.HashLength)
	nonZeroBytes[5] = 0xff
	nonZeroHash, _ := Sha256HashFromBytes(nonZeroBytes)
	assert.False(t, nonZeroHash.IsZero())
}
