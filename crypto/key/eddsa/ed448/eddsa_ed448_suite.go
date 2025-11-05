package ed448

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterKeySuite(&EdDSAEd448Suite{})
}

type EdDSAEd448Suite struct{}

var _ key.KeySuite = (*EdDSAEd448Suite)(nil)

func (s *EdDSAEd448Suite) Type() string {
	return eddsa.EdDSAEd448Type
}

func (s *EdDSAEd448Suite) GeneratePrivateKey() (key.PrivateKey, error) {
	return GenerateEdDSAEd448PrivateKey()
}

func (s *EdDSAEd448Suite) PrivateKeyFromBytes(data []byte) (key.PrivateKey, error) {
	return EdDSAEd448PrivateKeyFromBytes(data)
}

func (s *EdDSAEd448Suite) PublicKeyFromBytes(data []byte) (key.PublicKey, error) {
	return EdDSAEd448PublicKeyFromBytes(data)
}

func (s *EdDSAEd448Suite) SignatureFromBytes(data []byte) (key.Signature, error) {
	return EdDSAEd448SignatureFromBytes(data)
}
