package sha256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterAddressSuite(&Sha256AddressSuite{})
}

type Sha256AddressSuite struct{}

var _ kangaroohash.AddressSuite = (*Sha256AddressSuite)(nil)

func (s *Sha256AddressSuite) Type() string {
	return kangaroohash.Sha256Type
}

func (s *Sha256AddressSuite) Deriver() kangaroohash.AddressDeriver {
	return &Sha256AddressDeriver{}
}

func (s *Sha256AddressSuite) AddressFromBytes(data []byte) (kangaroohash.Address, error) {
	return Sha256AddressFromBytes(data)
}
