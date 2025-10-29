package keccak256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"strings"
)

const (
	Keccak256HashType = "keccak256-hash"
)

type Keccak256Hash [kangaroohash.HashLength]byte

var _ kangaroohash.Hashable = Keccak256Hash{}

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

func (h Keccak256Hash) Equal(other kangaroohash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Keccak256Hash) Gt(other kangaroohash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Keccak256Hash) Gte(other kangaroohash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Keccak256Hash) Lt(other kangaroohash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Keccak256Hash) Lte(other kangaroohash.Hashable) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Keccak256HashFromBytes(b []byte) (kangaroohash.Hashable, error) {
	if len(b) != kangaroohash.HashLength {
		return Keccak256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}

	var h Keccak256Hash

	copy(h[:], b)

	return h, nil
}

func Keccak256HashFromString(s string) (kangaroohash.Hashable, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangaroohash.HashHexLength {
		return Keccak256Hash{}, fmt.Errorf("invalid hex string length (%d), must be 64", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Keccak256Hash{}, err
	}

	return Keccak256HashFromBytes(b)
}

func FilledKeccak256Hash(b byte) kangaroohash.Hashable {
	var h Keccak256Hash
	for i := range kangaroohash.HashLength {
		h[i] = b
	}

	return h
}
