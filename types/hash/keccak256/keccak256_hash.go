package keccak256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/types/hash"
	"strings"
)

const (
	Keccak256HashType = "keccak256-hash"
)

type Keccak256Hash [hash.HashLength]byte

var _ hash.Hashable = Keccak256Hash{}
var _ hash.Hashable = (*Keccak256Hash)(nil)

func (h Keccak256Hash) Bytes() []byte {
	return h[:]
}

func (h Keccak256Hash) IsZero() bool {
	return h == Keccak256Hash{}
}

func (h Keccak256Hash) IsValid() bool {
	return !h.IsZero()
}

func (h Keccak256Hash) Type() string {
	return Keccak256HashType
}

func (h Keccak256Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h Keccak256Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h[:])

	if l > len(hs) {
		l = len(hs)
	}

	return "0x" + hs[:l]
}

func (h Keccak256Hash) Equal(other hash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Keccak256Hash) Gt(other hash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Keccak256Hash) Gte(other hash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Keccak256Hash) Lt(other hash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Keccak256Hash) Lte(other hash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Keccak256HashFromBytes(b []byte) (hash.Hashable, error) {
	if len(b) != hash.HashLength {
		return Keccak256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}

	var h Keccak256Hash

	copy(h[:], b)

	return h, nil
}

func Keccak256HashFromString(s string) (hash.Hashable, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != hash.HashHexLength {
		return Keccak256Hash{}, fmt.Errorf("invalid hex string length (%d), must be 64", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Keccak256Hash{}, err
	}

	return Keccak256HashFromBytes(b)
}

func FilledKeccak256Hash(b byte) hash.Hashable {
	var h Keccak256Hash
	for i := range hash.HashLength {
		h[i] = b
	}

	return h
}
