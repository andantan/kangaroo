package sha3

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha3Address [hash.AddressLength]byte

var _ hash.Address = Sha3Address{}

func (a Sha3Address) Bytes() []byte {
	return a[:]
}

func (a Sha3Address) IsZero() bool {
	return a == Sha3Address{}
}

func (a Sha3Address) IsValid() bool {
	return !a.IsZero()
}

func (a Sha3Address) Type() string {
	return hash.Sha3Type
}

func (a Sha3Address) String() string {
	return "0x" + hex.EncodeToString(a.Bytes())
}

func (a Sha3Address) ShortString(l int) string {
	as := hex.EncodeToString(a.Bytes())

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Sha3Address) Equal(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha3Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Sha3Address) Gt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha3Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Sha3Address) Gte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha3Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Sha3Address) Lt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha3Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Sha3Address) Lte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Sha3Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Sha3AddressFromBytes(b []byte) (hash.Address, error) {
	if len(b) != hash.AddressLength {
		return Sha3Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}
	var a Sha3Address
	copy(a[:], b)
	return a, nil
}
