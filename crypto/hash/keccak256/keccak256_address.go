package keccak256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

type Keccak256Address [kangaroohash.AddressLength]byte

var _ kangaroohash.Address = Keccak256Address{}

func (a Keccak256Address) Bytes() []byte {
	prefix, err := kangarooregistry.GetAddressPrefixFromType(a.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration address<%s> panic: %v", a.Type(), err))
	}
	return append([]byte{prefix}, a[:]...)
}

func (a Keccak256Address) IsZero() bool {
	return a == Keccak256Address{}
}

func (a Keccak256Address) IsValid() bool {
	return !a.IsZero()
}

func (a Keccak256Address) Type() string {
	return kangaroohash.Keccak256Type
}

func (a Keccak256Address) String() string {
	return "0x" + hex.EncodeToString(a.Bytes())
}

func (a Keccak256Address) ShortString(l int) string {
	as := hex.EncodeToString(a.Bytes())

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Keccak256Address) Equal(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Keccak256Address) Gt(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Keccak256Address) Gte(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Keccak256Address) Lt(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Keccak256Address) Lte(other kangaroohash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Keccak256AddressFromBytes(b []byte) (kangaroohash.Address, error) {
	if len(b) != kangaroohash.AddressLength {
		return Keccak256Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}

	var a Keccak256Address

	copy(a[:], b)

	return a, nil
}
