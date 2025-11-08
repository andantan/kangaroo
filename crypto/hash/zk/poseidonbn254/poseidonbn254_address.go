package poseidonbn254

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type PoseidonBN254Address [hash.AddressLength]byte

var _ hash.Address = PoseidonBN254Address{}

func (a PoseidonBN254Address) Bytes() []byte {
	return a[:]
}

func (a PoseidonBN254Address) IsZero() bool {
	return a == PoseidonBN254Address{}
}

func (a PoseidonBN254Address) IsValid() bool {
	return !a.IsZero()
}

func (a PoseidonBN254Address) Type() string {
	return hash.PoseidonBN254Type
}

func (a PoseidonBN254Address) String() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (a PoseidonBN254Address) ShortString(length int) string {
	as := hex.EncodeToString(a.Bytes())
	if length > len(as) {
		length = len(as)
	}
	return "0x" + as[:length]
}

func (a PoseidonBN254Address) Equal(other hash.Address) bool {
	otherAddress, ok := other.(PoseidonBN254Address)
	if !ok {
		return false
	}
	return a == otherAddress
}

func (a PoseidonBN254Address) Gt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(PoseidonBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) > 0
}

func (a PoseidonBN254Address) Gte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(PoseidonBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) >= 0
}

func (a PoseidonBN254Address) Lt(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(PoseidonBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) < 0
}

func (a PoseidonBN254Address) Lte(other hash.Address) bool {
	if other == nil {
		return false
	}

	otherAddress, ok := other.(PoseidonBN254Address)
	if !ok {
		return false
	}

	return bytes.Compare(a.Bytes(), otherAddress.Bytes()) <= 0
}

func PoseidonBN254AddressFromBytes(b []byte) (hash.Address, error) {
	if len(b) != hash.AddressLength {
		return PoseidonBN254Address{}, fmt.Errorf("given bytes with address-length %d should be 20 bytes", len(b))
	}
	var a PoseidonBN254Address
	copy(a[:], b)
	return a, nil
}
