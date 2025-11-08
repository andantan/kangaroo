package poseidonbn254

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type PoseidonBN254Hash [hash.HashLength]byte

var _ hash.Hash = PoseidonBN254Hash{}

func (h PoseidonBN254Hash) Bytes() []byte {
	return h[:]
}

func (h PoseidonBN254Hash) IsZero() bool {
	return h == PoseidonBN254Hash{}
}

func (h PoseidonBN254Hash) IsValid() bool {
	return !h.IsZero()
}

func (h PoseidonBN254Hash) Type() string {
	return hash.PoseidonBN254Type
}

func (h PoseidonBN254Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h PoseidonBN254Hash) ShortString(length int) string {
	hs := hex.EncodeToString(h.Bytes())

	if length > len(hs) {
		length = len(hs)
	}

	return "0x" + hs[:length]
}

func (h PoseidonBN254Hash) Equal(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(PoseidonBN254Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h PoseidonBN254Hash) Gt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(PoseidonBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h PoseidonBN254Hash) Gte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(PoseidonBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h PoseidonBN254Hash) Lt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(PoseidonBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h PoseidonBN254Hash) Lte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(PoseidonBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func PoseidonBN254HashFromBytes(b []byte) (hash.Hash, error) {
	if len(b) != hash.HashLength {
		return PoseidonBN254Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}
	var h PoseidonBN254Hash
	copy(h[:], b)
	return h, nil
}
