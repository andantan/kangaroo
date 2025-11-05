package sha3

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&Sha3AddressSuite{})
}

type Sha3AddressSuite struct{}

var _ hash.AddressSuite = (*Sha3AddressSuite)(nil)

func (_ *Sha3AddressSuite) Type() string {
	return hash.Sha3Type
}

func (_ *Sha3AddressSuite) Deriver() hash.AddressDeriver {
	return &Sha3AddressDeriver{}
}

func (_ *Sha3AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return Sha3AddressFromBytes(data)
}
