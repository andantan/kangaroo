package blake2b256

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Blake2b256Address [hash.AddressLength]byte

var _ hash.Address = Blake2b256Address{}

func (a Blake2b256Address) Bytes() []byte {
	return a[:]
}

func (a Blake2b256Address) IsZero() bool {
	return a == Blake2b256Address{}
}

func (a Blake2b256Address) IsValid() bool {
	return !a.IsZero()
}

func (a Blake2b256Address) Type() string {
	return hash.Blake2b256Type
}

func (a Blake2b256Address) String() string {
	return "0x" + hex.EncodeToString(a.Bytes())
}

func (a Blake2b256Address) ShortString(l int) string {
	as := hex.EncodeToString(a.Bytes())

	if l > len(as) {
		l = len(as)
	}

	return "0x" + as[:l]
}

func (a Blake2b256Address) Equal(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Blake2b256Address)
	if !ok {
		return false
	}

	return a == otherAddress
}

func (a Blake2b256Address) Gt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Blake2b256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a Blake2b256Address) Gte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Blake2b256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a Blake2b256Address) Lt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Blake2b256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a Blake2b256Address) Lte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(Blake2b256Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func Blake2b256AddressFromBytes(b []byte) (hash.Address, error) {
	if len(b) != hash.AddressLength {
		return Blake2b256Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}
	var a Blake2b256Address
	copy(a[:], b)
	return a, nil
}
