package sha256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"strings"
)

const (
	Sha256AddressType = "sha256-address"
)

type Sha256Address [hash.AddressLength]byte

var _ hash.Addressable = Sha256Address{}
var _ hash.Addressable = (*Sha256Address)(nil)

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
	return Sha256AddressType
}

func (a Sha256Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a Sha256Address) ShortString(l int) string {
	as := hex.EncodeToString(a[:])

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Sha256Address) Equal(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Sha256Address) Gt(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Sha256Address) Gte(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Sha256Address) Lt(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Sha256Address) Lte(other hash.Addressable) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Sha256AddressFromBytes(b []byte) (hash.Addressable, error) {
	if len(b) != hash.AddressLength {
		return Sha256Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}

	var a Sha256Address

	copy(a[:], b)

	return a, nil
}

func Sha256AddressFromString(s string) (hash.Addressable, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != hash.AddressHexLength {
		return Sha256Address{}, fmt.Errorf("invalid hex string length (%d), must be 40", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Sha256Address{}, err
	}

	return Sha256AddressFromBytes(b)
}

func FilledSha256Address(b byte) hash.Addressable {
	var a Sha256Address
	for i := range hash.AddressLength {
		a[i] = b
	}

	return a
}
