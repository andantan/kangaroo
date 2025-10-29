package keccak256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/types/hash"
	"strings"
)

const (
	Keccak256AddressType = "keccak256-address"
)

type Keccak256Address [hash.AddressLength]byte

var _ hash.Addressable = Keccak256Address{}
var _ hash.Addressable = (*Keccak256Address)(nil)

func (a Keccak256Address) Bytes() []byte {
	return a[:]
}

func (a Keccak256Address) IsZero() bool {
	return a == Keccak256Address{}
}

func (a Keccak256Address) IsValid() bool {
	return !a.IsZero()
}

func (a Keccak256Address) Type() string {
	return Keccak256AddressType
}

func (a Keccak256Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a Keccak256Address) ShortString(l int) string {
	as := hex.EncodeToString(a[:])

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Keccak256Address) Equal(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Keccak256Address) Gt(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Keccak256Address) Gte(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Keccak256Address) Lt(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Keccak256Address) Lte(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Keccak256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Keccak256AddressFromBytes(b []byte) (hash.Addressable, error) {
	if len(b) != hash.AddressLength {
		return Keccak256Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}

	var a Keccak256Address

	copy(a[:], b)

	return a, nil
}

func Keccak256AddressFromString(s string) (hash.Addressable, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != hash.AddressHexLength {
		return Keccak256Address{}, fmt.Errorf("invalid hex string length (%d), must be 40", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Keccak256Address{}, err
	}

	return Keccak256AddressFromBytes(b)
}

func FilledKeccak256Address(b byte) hash.Addressable {
	var a Keccak256Address
	for i := range hash.AddressLength {
		a[i] = b
	}

	return a
}
