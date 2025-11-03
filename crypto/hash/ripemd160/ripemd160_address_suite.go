package ripemd160

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterAddressSuite(&Ripemd160AddressSuite{})
}

type Ripemd160AddressSuite struct{}

var _ kangaroohash.AddressSuite = (*Ripemd160AddressSuite)(nil)

func (s *Ripemd160AddressSuite) Type() string {
	return kangaroohash.Ripemd160Type
}

func (s *Ripemd160AddressSuite) Deriver() kangaroohash.AddressDeriver {
	return &Ripemd160AddressDeriver{}
}

func (s *Ripemd160AddressSuite) AddressFromBytes(data []byte) (kangaroohash.Address, error) {
	return Ripemd160AddressFromBytes(data)
}
