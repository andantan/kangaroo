package sha256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterHashSuite(&Sha256HashSuite{})
}

type Sha256HashSuite struct{}

var _ kangaroohash.HashSuite = (*Sha256HashSuite)(nil)

func (s *Sha256HashSuite) Type() string {
	return kangaroohash.Sha256Type
}

func (s *Sha256HashSuite) Deriver() kangaroohash.HashDeriver {
	return &Sha256HashDeriver{}
}

func (s *Sha256HashSuite) HashFromBytes(data []byte) (kangaroohash.Hash, error) {
	return Sha256HashFromBytes(data)
}
