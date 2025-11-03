package keccak256

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterHashSuite(&Keccak256HashSuite{})
}

type Keccak256HashSuite struct{}

var _ kangaroohash.HashSuite = (*Keccak256HashSuite)(nil)

func (s *Keccak256HashSuite) Type() string {
	return kangaroohash.Keccak256Type
}

func (s *Keccak256HashSuite) Deriver() kangaroohash.HashDeriver {
	return &Keccak256HashDeriver{}
}

func (s *Keccak256HashSuite) HashFromBytes(data []byte) (kangaroohash.Hash, error) {
	return Keccak256HashFromBytes(data)
}
