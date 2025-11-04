package sha256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha256Hash [hash.HashLength]byte

var _ hash.Hash = Sha256Hash{}

func (h Sha256Hash) Bytes() []byte {
	return h[:]
}

func (h Sha256Hash) IsZero() bool {
	return h == Sha256Hash{}
}

func (h Sha256Hash) IsValid() bool {
	return !h.IsZero()
}

func (h Sha256Hash) Type() string {
	return hash.Sha256Type
}

func (h Sha256Hash) String() string {
	return "0x" + hex.EncodeToString(h.Bytes())
}

func (h Sha256Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h.Bytes())

	if l > len(hs) {
		l = len(hs)
	}

	return "0x" + hs[:l]
}

func (h Sha256Hash) Equal(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Sha256Hash) Gt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Sha256Hash) Gte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Sha256Hash) Lt(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Sha256Hash) Lte(other hash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Sha256HashFromBytes(b []byte) (hash.Hash, error) {
	if len(b) != hash.HashLength {
		return Sha256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}
	var h Sha256Hash
	copy(h[:], b)
	return h, nil
}
