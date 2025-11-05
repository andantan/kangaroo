package blake2b256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Blake2b256Hash [hash.HashLength]byte

var _ hash.Hash = Blake2b256Hash{}

func (h Blake2b256Hash) Bytes() []byte {
	return h[:]
}
func (h Blake2b256Hash) IsZero() bool {
	return h == Blake2b256Hash{}
}
func (h Blake2b256Hash) IsValid() bool {
	return !h.IsZero()
}
func (h Blake2b256Hash) Type() string {
	return hash.Blake2b256Type
}
func (h Blake2b256Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}
func (h Blake2b256Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h[:])
	if l > len(hs) {
		l = len(hs)
	}
	return "0x" + hs[:l]
}
func (h Blake2b256Hash) Equal(other hash.Hash) bool {
	otherHash, ok := other.(Blake2b256Hash)
	if !ok {
		return false
	}
	return h == otherHash
}

func (h Blake2b256Hash) Gt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Blake2b256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Blake2b256Hash) Gte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Blake2b256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Blake2b256Hash) Lt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Blake2b256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Blake2b256Hash) Lte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Blake2b256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Blake2b256HashFromBytes(b []byte) (hash.Hash, error) {
	if len(b) != hash.HashLength {
		return Blake2b256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}
	var h Blake2b256Hash
	copy(h[:], b)
	return h, nil
}
