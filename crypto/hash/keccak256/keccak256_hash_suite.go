package keccak256

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterHashSuite(&Keccak256HashSuite{})
}

type Keccak256HashSuite struct{}

var _ hash.HashSuite = (*Keccak256HashSuite)(nil)

func (s *Keccak256HashSuite) Type() string {
	return hash.Keccak256Type
}

func (s *Keccak256HashSuite) Deriver() hash.HashDeriver {
	return &Keccak256HashDeriver{}
}

func (s *Keccak256HashSuite) HashFromBytes(data []byte) (hash.Hash, error) {
	return Keccak256HashFromBytes(data)
}
