package sha256

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&Sha256AddressSuite{})
}

type Sha256AddressSuite struct{}

var _ hash.AddressSuite = (*Sha256AddressSuite)(nil)

func (s *Sha256AddressSuite) Type() string {
	return hash.Sha256Type
}

func (s *Sha256AddressSuite) Deriver() hash.AddressDeriver {
	return &Sha256AddressDeriver{}
}

func (s *Sha256AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return Sha256AddressFromBytes(data)
}
