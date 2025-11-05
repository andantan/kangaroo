package mimcbn254

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type MimcBN254Address [hash.AddressLength]byte

var _ hash.Address = MimcBN254Address{}

func (a MimcBN254Address) Bytes() []byte {
	return a[:]
}

func (a MimcBN254Address) IsZero() bool {
	return a == MimcBN254Address{}
}

func (a MimcBN254Address) IsValid() bool {
	return !a.IsZero()
}

func (a MimcBN254Address) Type() string {
	return hash.MimcBN254Type
}

func (a MimcBN254Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a MimcBN254Address) ShortString(l int) string {
	as := hex.EncodeToString(a.Bytes())
	if l > len(as) {
		l = len(as)
	}
	return "0x" + as[:l]
}

func (a MimcBN254Address) Equal(other hash.Address) bool {
	otherAddress, ok := other.(MimcBN254Address)
	if !ok {
		return false
	}
	return a == otherAddress
}

func (a MimcBN254Address) Gt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(MimcBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a MimcBN254Address) Gte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(MimcBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a MimcBN254Address) Lt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(MimcBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a MimcBN254Address) Lte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(MimcBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func MimcBN254AddressFromBytes(b []byte) (hash.Address, error) {
	if len(b) != hash.AddressLength {
		return MimcBN254Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}
	var a MimcBN254Address
	copy(a[:], b)
	return a, nil
}
