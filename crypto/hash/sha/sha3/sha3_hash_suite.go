package sha3

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterHashSuite(&Sha3HashSuite{})
}

type Sha3HashSuite struct{}

var _ hash.HashSuite = (*Sha3HashSuite)(nil)

func (_ *Sha3HashSuite) Type() string {
	return hash.Sha3Type
}

func (_ *Sha3HashSuite) Deriver() hash.HashDeriver {
	return &Sha3HashDeriver{}
}

func (_ *Sha3HashSuite) HashFromBytes(data []byte) (hash.Hash, error) {
	return Sha3HashFromBytes(data)
}
