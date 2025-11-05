package blake2b256

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterHashSuite(&Blake2b256HashSuite{})
}

type Blake2b256HashSuite struct{}

var _ hash.HashSuite = (*Blake2b256HashSuite)(nil)

func (_ *Blake2b256HashSuite) Type() string {
	return hash.Blake2b256Type
}

func (_ *Blake2b256HashSuite) Deriver() hash.HashDeriver {
	return &Blake2b256HashDeriver{}
}

func (_ *Blake2b256HashSuite) HashFromBytes(data []byte) (hash.Hash, error) {
	return Blake2b256HashFromBytes(data)
}
