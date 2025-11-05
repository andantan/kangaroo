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

func (_ *Sha256AddressSuite) Type() string {
	return hash.Sha256Type
}

func (_ *Sha256AddressSuite) Deriver() hash.AddressDeriver {
	return &Sha256AddressDeriver{}
}

func (_ *Sha256AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return Sha256AddressFromBytes(data)
}
