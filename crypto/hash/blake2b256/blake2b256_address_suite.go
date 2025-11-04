package blake2b256

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterAddressSuite(&Blake2b256AddressSuite{})
}

type Blake2b256AddressSuite struct{}

var _ hash.AddressSuite = (*Blake2b256AddressSuite)(nil)

func (_ *Blake2b256AddressSuite) Type() string {
	return hash.Blake2b256Type
}

func (_ *Blake2b256AddressSuite) Deriver() hash.AddressDeriver {
	return &Blake2b256AddressDeriver{}
}

func (_ *Blake2b256AddressSuite) AddressFromBytes(data []byte) (hash.Address, error) {
	return Blake2b256AddressFromBytes(data)
}
