package sha256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha256Address [hash.AddressLength]byte

var _ hash.Address = Sha256Address{}

func (a Sha256Address) Bytes() []byte {
	return a[:]
}

func (a Sha256Address) IsZero() bool {
	return a == Sha256Address{}
}

func (a Sha256Address) IsValid() bool {
	return !a.IsZero()
}

func (a Sha256Address) Type() string {
	return hash.Sha256Type
}

func (a Sha256Address) String() string {
	return "0x" + hex.EncodeToString(a.Bytes())
}

func (a Sha256Address) ShortString(length int) string {
	as := hex.EncodeToString(a.Bytes())

	if length > len(as) {
		length = len(as)
	}

	return "0x" + as[:length]
}

func (a Sha256Address) Equal(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Sha256Address) Gt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Sha256Address) Gte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Sha256Address) Lt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Sha256Address) Lte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Sha256AddressFromBytes(b []byte) (hash.Address, error) {
	if len(b) != hash.AddressLength {
		return Sha256Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}
	var a Sha256Address
	copy(a[:], b)
	return a, nil
}
