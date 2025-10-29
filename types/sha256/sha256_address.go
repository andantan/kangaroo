package sha256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/types"
	"strings"
)

const (
	SHA256AddressType = "sha256-address"
)

type SHA256Address [types.AddressLength]uint8

var _ types.Addressable = SHA256Address{}
var _ types.Addressable = (*SHA256Address)(nil)

func (a SHA256Address) Bytes() []byte {
	return a[:]
}

func (a SHA256Address) IsZero() bool {
	return a == SHA256Address{}
}

func (a SHA256Address) IsValid() bool {
	return !a.IsZero()
}

func (a SHA256Address) Type() string {
	return SHA256AddressType
}

func (a SHA256Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a SHA256Address) ShortString(l int) string {
	as := hex.EncodeToString(a[:])

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a SHA256Address) Equal(other types.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(SHA256Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a SHA256Address) Gt(other types.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(SHA256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a SHA256Address) Gte(other types.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(SHA256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a SHA256Address) Lt(other types.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(SHA256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a SHA256Address) Lte(other types.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(SHA256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func SHA256AddressFromBytes(b []byte) (SHA256Address, error) {
	if len(b) != types.AddressLength {
		return SHA256Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}

	var a SHA256Address

	copy(a[:], b)

	return a, nil
}

func SHA256AddressFromString(s string) (SHA256Address, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != types.AddressHexLength {
		return SHA256Address{}, fmt.Errorf("invalid hex string length (%d), must be 40", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return SHA256Address{}, err
	}

	return SHA256AddressFromBytes(b)
}

func FilledSHA256Address(b byte) SHA256Address {
	var addr SHA256Address
	for i := range types.AddressLength {
		addr[i] = b
	}

	return addr
}
