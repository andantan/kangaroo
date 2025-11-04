package ripemd160

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&Ripemd160AddressSuite{})
}

type Ripemd160AddressSuite struct{}

var _ hash.AddressSuite = (*Ripemd160AddressSuite)(nil)

func (s *Ripemd160AddressSuite) Type() string {
	return hash.Ripemd160Type
}

func (s *Ripemd160AddressSuite) Deriver() hash.AddressDeriver {
	return &Ripemd160AddressDeriver{}
}

func (s *Ripemd160AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return Ripemd160AddressFromBytes(data)
}
