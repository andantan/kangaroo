package keccak256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

type Keccak256Hash [kangaroohash.HashLength]byte

var _ kangaroohash.Hash = Keccak256Hash{}

func (h Keccak256Hash) Bytes() []byte {
	prefix, err := kangarooregistry.GetHashPrefixFromType(h.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration hash<%s> panic: %v", h.Type(), err))
	}
	return append([]byte{prefix}, h[:]...)
}

func (h Keccak256Hash) IsZero() bool {
	return h == Keccak256Hash{}
}

func (h Keccak256Hash) IsValid() bool {
	return !h.IsZero()
}

func (h Keccak256Hash) Type() string {
	return kangaroohash.Keccak256Type
}

func (h Keccak256Hash) String() string {
	return "0x" + hex.EncodeToString(h.Bytes())
}

func (h Keccak256Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h.Bytes())

	if l > len(hs) {
		l = len(hs)
	}

	return "0x" + hs[:l]
}

func (h Keccak256Hash) Equal(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Keccak256Hash) Gt(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Keccak256Hash) Gte(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Keccak256Hash) Lt(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Keccak256Hash) Lte(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Keccak256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Keccak256HashFromBytes(b []byte) (kangaroohash.Hash, error) {
	if len(b) != kangaroohash.HashLength {
		return Keccak256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}

	var h Keccak256Hash

	copy(h[:], b)

	return h, nil
}
