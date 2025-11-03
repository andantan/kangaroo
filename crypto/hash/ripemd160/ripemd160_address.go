package ripemd160

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

type Ripemd160Address [kangaroohash.AddressLength]byte

var _ kangaroohash.Address = Ripemd160Address{}

func (a Ripemd160Address) Bytes() []byte {
	prefix, err := kangarooregistry.GetAddressPrefixFromType(a.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration address<%s> panic: %v", a.Type(), err))
	}
	return append([]byte{prefix}, a[:]...)
}

func (a Ripemd160Address) IsZero() bool {
	return a == Ripemd160Address{}
}

func (a Ripemd160Address) IsValid() bool {
	return !a.IsZero()
}

func (a Ripemd160Address) Type() string {
	return kangaroohash.Ripemd160Type
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

func (a Ripemd160Address) Equal(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Ripemd160Address) Gt(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Ripemd160Address) Gte(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Ripemd160Address) Lt(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Ripemd160Address) Lte(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Ripemd160AddressFromBytes(b []byte) (kangaroohash.Address, error) {
	if len(b) != kangaroohash.AddressLength {
		return Ripemd160Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}

	var a Ripemd160Address

	copy(a[:], b)

	return a, nil
}
