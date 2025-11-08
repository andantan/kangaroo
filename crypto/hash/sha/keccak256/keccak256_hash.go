package keccak256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Keccak256Hash [hash.HashLength]byte

var _ hash.Hash = Keccak256Hash{}

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
	return hash.Keccak256Type
}

func (h Keccak256Hash) String() string {
	return "0x" + hex.EncodeToString(h.Bytes())
}

func (h Keccak256Hash) ShortString(length int) string {
	hs := hex.EncodeToString(h.Bytes())

	if length > len(hs) {
		length = len(hs)
	}

	return "0x" + hs[:length]
}

func (h Keccak256Hash) Equal(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Keccak256Hash) Gt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Keccak256Hash) Gte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Keccak256Hash) Lt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Keccak256Hash) Lte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Keccak256HashFromBytes(b []byte) (hash.Hash, error) {
	if len(b) != hash.HashLength {
		return Keccak256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}
	var h Keccak256Hash
	copy(h[:], b)
	return h, nil
}
