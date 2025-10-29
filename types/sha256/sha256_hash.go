package sha256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/types"
	"strings"
)

const (
	SHA256HashType = "sha256-hash"
)

type SHA256Hash [types.HashLength]uint8

var _ types.Hashable = SHA256Hash{}
var _ types.Hashable = (*SHA256Hash)(nil)

func (h SHA256Hash) Bytes() []byte {
	return h[:]
}

func (h SHA256Hash) IsZero() bool {
	return h == SHA256Hash{}
}

func (h SHA256Hash) IsValid() bool {
	return !h.IsZero()
}

func (h SHA256Hash) Type() string {
	return SHA256HashType
}

func (h SHA256Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h SHA256Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h[:])

	if l > len(hs) {
		l = len(hs)
	}

	return "0x" + hs[:l]
}

func (h SHA256Hash) Equal(other types.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(SHA256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h SHA256Hash) Gt(other types.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(SHA256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h SHA256Hash) Gte(other types.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(SHA256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h SHA256Hash) Lt(other types.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(SHA256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h SHA256Hash) Lte(other types.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(SHA256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func SHA256HashFromBytes(b []byte) (SHA256Hash, error) {
	if len(b) != types.HashLength {
		return SHA256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}

	var h SHA256Hash

	copy(h[:], b)

	return h, nil
}

func SHA256HashFromString(s string) (SHA256Hash, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != types.HashHexLength {
		return SHA256Hash{}, fmt.Errorf("invalid hex string length (%d), must be 64", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return SHA256Hash{}, err
	}

	return SHA256HashFromBytes(b)
}

func FilledSHA256Hash(b byte) SHA256Hash {
	var hash SHA256Hash
	for i := range types.HashLength {
		hash[i] = b
	}

	return hash
}
