package sha3

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha3Hash [hash.HashLength]byte

var _ hash.Hash = Sha3Hash{}

func (h Sha3Hash) Bytes() []byte {
	return h[:]
}

func (h Sha3Hash) IsZero() bool {
	return h == Sha3Hash{}
}

func (h Sha3Hash) IsValid() bool {
	return !h.IsZero()
}

func (h Sha3Hash) Type() string {
	return hash.Sha3Type
}

func (h Sha3Hash) String() string {
	return "0x" + hex.EncodeToString(h.Bytes())
}

func (h Sha3Hash) ShortString(length int) string {
	hs := hex.EncodeToString(h.Bytes())

	if length > len(hs) {
		length = len(hs)
	}

	return "0x" + hs[:length]
}

func (h Sha3Hash) Equal(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha3Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Sha3Hash) Gt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha3Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Sha3Hash) Gte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha3Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Sha3Hash) Lt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha3Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Sha3Hash) Lte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha3Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Sha3HashFromBytes(b []byte) (hash.Hash, error) {
	if len(b) != hash.HashLength {
		return Sha3Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}
	var h Sha3Hash
	copy(h[:], b)
	return h, nil
}
