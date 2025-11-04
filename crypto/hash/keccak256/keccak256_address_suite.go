package keccak256

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&Keccak256AddressSuite{})
}

type Keccak256AddressSuite struct{}

var _ hash.AddressSuite = (*Keccak256AddressSuite)(nil)

func (s *Keccak256AddressSuite) Type() string {
	return hash.Keccak256Type
}

func (s *Keccak256AddressSuite) Deriver() hash.AddressDeriver {
	return &Keccak256AddressDeriver{}
}

func (s *Keccak256AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return Keccak256AddressFromBytes(data)
}
