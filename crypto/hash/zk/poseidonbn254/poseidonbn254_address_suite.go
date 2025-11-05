package poseidonbn254

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&PoseidonBN254AddressSuite{})
}

type PoseidonBN254AddressSuite struct{}

var _ hash.AddressSuite = (*PoseidonBN254AddressSuite)(nil)

func (_ *PoseidonBN254AddressSuite) Type() string {
	return hash.PoseidonBN254Type
}

func (_ *PoseidonBN254AddressSuite) Deriver() hash.AddressDeriver {
	return &PoseidonBN254AddressDeriver{}
}

func (_ *PoseidonBN254AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return PoseidonBN254AddressFromBytes(data)
}
