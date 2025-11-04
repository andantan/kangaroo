package ed25519

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterKeySuite(&EdDSAEd25519Suite{})
}

type EdDSAEd25519Suite struct{}

var _ key.KeySuite = (*EdDSAEd25519Suite)(nil)

func (s *EdDSAEd25519Suite) Type() string {
	return eddsa.EdDSAEd25519Type
}

func (s *EdDSAEd25519Suite) GeneratePrivateKey() (key.PrivateKey, error) {
	return GenerateEdDSAEd25519PrivateKey()
}

func (s *EdDSAEd25519Suite) PrivateKeyFromBytes(data []byte) (key.PrivateKey, error) {
	return EdDSAEd25519PrivateKeyFromBytes(data)
}

func (s *EdDSAEd25519Suite) PublicKeyFromBytes(data []byte) (key.PublicKey, error) {
	return EdDSAEd25519PublicKeyFromBytes(data)
}

func (s *EdDSAEd25519Suite) SignatureFromBytes(data []byte) (key.Signature, error) {
	return EdDSAEd25519SignatureFromBytes(data)
}
