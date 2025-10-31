package sha256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"strings"
)

type Sha256Hash [kangaroohash.HashLength]byte

var _ kangaroohash.Hash = Sha256Hash{}

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
	return kangaroohash.Sha256Type
}

func (h Sha256Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h Sha256Hash) ShortString(l int) string {
	hs := hex.EncodeToString(h[:])

	if l > len(hs) {
		l = len(hs)
	}

	return "0x" + hs[:l]
}

func (h Sha256Hash) Equal(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return h == otherHash
}

func (h Sha256Hash) Gt(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) > 0
}

func (h Sha256Hash) Gte(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) >= 0
}

func (h Sha256Hash) Lt(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) < 0
}

func (h Sha256Hash) Lte(other kangaroohash.Hash) bool {
	if other == nil {
		return false
	}

	otherHash, ok := other.(Sha256Hash)
	if !ok {
		return false
	}

	return bytes.Compare(h.Bytes(), otherHash.Bytes()) <= 0
}

func Sha256HashFromBytes(b []byte) (kangaroohash.Hash, error) {
	if len(b) != kangaroohash.HashLength {
		return Sha256Hash{}, fmt.Errorf("given bytes with hash-length %d should be 32 bytes", len(b))
	}

	var h Sha256Hash

	copy(h[:], b)

	return h, nil
}

func Sha256HashFromString(s string) (kangaroohash.Hash, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangaroohash.HashHexLength {
		return Sha256Hash{}, fmt.Errorf("invalid hex string length (%d), must be 64", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Sha256Hash{}, err
	}

	return Sha256HashFromBytes(b)
}

func FilledSha256Hash(b byte) kangaroohash.Hash {
	var h Sha256Hash
	for i := range kangaroohash.HashLength {
		h[i] = b
	}

	return h
}
