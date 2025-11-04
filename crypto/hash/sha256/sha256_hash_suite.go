package sha256

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterHashSuite(&Sha256HashSuite{})
}

type Sha256HashSuite struct{}

var _ hash.HashSuite = (*Sha256HashSuite)(nil)

func (s *Sha256HashSuite) Type() string {
	return hash.Sha256Type
}

func (s *Sha256HashSuite) Deriver() hash.HashDeriver {
	return &Sha256HashDeriver{}
}

func (s *Sha256HashSuite) HashFromBytes(data []byte) (hash.Hash, error) {
	return Sha256HashFromBytes(data)
}
