package ripemd160

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"strings"
)

type Ripemd160Address [kangaroohash.AddressLength]byte

var _ kangaroohash.Addressable = Ripemd160Address{}

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
	return kangaroohash.Ripemd160Type
}

func (a Ripemd160Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a Ripemd160Address) ShortString(l int) string {
	as := hex.EncodeToString(a[:])

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Ripemd160Address) Equal(other kangaroohash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Ripemd160Address) Gt(other kangaroohash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Ripemd160Address) Gte(other kangaroohash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Ripemd160Address) Lt(other kangaroohash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Ripemd160Address) Lte(other kangaroohash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Ripemd160Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Ripemd160AddressFromBytes(b []byte) (kangaroohash.Addressable, error) {
	if len(b) != kangaroohash.AddressLength {
		return Ripemd160Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}

	var a Ripemd160Address

	copy(a[:], b)

	return a, nil
}

func Ripemd160AddressFromString(s string) (kangaroohash.Addressable, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangaroohash.AddressHexLength {
		return Ripemd160Address{}, fmt.Errorf("invalid hex string length (%d), must be 40", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Ripemd160Address{}, err
	}

	return Ripemd160AddressFromBytes(b)
}

func FilledRipemd160Address(b byte) kangaroohash.Addressable {
	var a Ripemd160Address
	for i := range kangaroohash.AddressLength {
		a[i] = b
	}

	return a
}
