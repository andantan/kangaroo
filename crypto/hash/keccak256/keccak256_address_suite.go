package keccak256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterAddressSuite(&Keccak256AddressSuite{})
}

type Keccak256AddressSuite struct{}

var _ kangaroohash.AddressSuite = (*Keccak256AddressSuite)(nil)

func (s *Keccak256AddressSuite) Type() string {
	return kangaroohash.Keccak256Type
}

func (s *Keccak256AddressSuite) Deriver() kangaroohash.AddressDeriver {
	return &Keccak256AddressDeriver{}
}

func (s *Keccak256AddressSuite) AddressFromBytes(data []byte) (kangaroohash.Address, error) {
	return Keccak256AddressFromBytes(data)
}
