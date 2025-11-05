package ripemd160

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Ripemd160Address [hash.AddressLength]byte

var _ hash.Address = Ripemd160Address{}

func (a Ripemd160Address) Bytes() []byte {
	return a[:]
}

func (a Ripemd160Address) IsZero() bool {
	return a == Ripemd160Address{}
}

func (a Ripemd160Address) IsValid() bool {
	return !a.IsZero()
}

func (a Ripemd160Address) Type() string {
	return hash.Ripemd160Type
}

func (a Ripemd160Address) String() string {
	return "0x" + hex.EncodeToString(a.Bytes())
}

func (a Ripemd160Address) ShortString(l int) string {
	as := hex.EncodeToString(a.Bytes())

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Ripemd160Address) Equal(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Ripemd160Address) Gt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Ripemd160Address) Gte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Ripemd160Address) Lt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Ripemd160Address) Lte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Ripemd160AddressFromBytes(b []byte) (hash.Address, error) {
	if len(b) != hash.AddressLength {
		return Ripemd160Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}
	var a Ripemd160Address
	copy(a[:], b)
	return a, nil
}
