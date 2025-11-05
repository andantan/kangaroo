package mimcbn254

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&MimcBN254AddressSuite{})
}

type MimcBN254AddressSuite struct{}

var _ hash.AddressSuite = (*MimcBN254AddressSuite)(nil)

func (_ *MimcBN254AddressSuite) Type() string {
	return hash.MimcBN254Type
}

func (_ *MimcBN254AddressSuite) Deriver() hash.AddressDeriver {
	return &MimcBN254AddressDeriver{}
}

func (_ *MimcBN254AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return MimcBN254AddressFromBytes(data)
}
