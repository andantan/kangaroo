package mimcbn254

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type MimcBN254Hash [hash.HashLength]byte

var _ hash.Hash = MimcBN254Hash{}

func (h MimcBN254Hash) Bytes() []byte {
	return h[:]
}

func (h MimcBN254Hash) IsZero() bool {
	return h == MimcBN254Hash{}
}

func (h MimcBN254Hash) IsValid() bool {
	return !h.IsZero()
}

func (h MimcBN254Hash) Type() string {
	return hash.MimcBN254Type
}

func (h MimcBN254Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h MimcBN254Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h.Bytes())

	if l > len(hs) {
		l = len(hs)
	}

	return "0x" + hs[:l]
}

func (h MimcBN254Hash) Equal(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(MimcBN254Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h MimcBN254Hash) Gt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(MimcBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h MimcBN254Hash) Gte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(MimcBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h MimcBN254Hash) Lt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(MimcBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h MimcBN254Hash) Lte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(MimcBN254Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func MimcBN254HashFromBytes(b []byte) (hash.Hash, error) {
	if len(b) != hash.HashLength {
		return MimcBN254Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}
	var h MimcBN254Hash
	copy(h[:], b)
	return h, nil
}
