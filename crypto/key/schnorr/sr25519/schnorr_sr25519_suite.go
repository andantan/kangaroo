package sr25519

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterKeySuite(&SchnorrSr25519Suite{})
}

type SchnorrSr25519Suite struct{}

var _ key.KeySuite = (*SchnorrSr25519Suite)(nil)

func (s *SchnorrSr25519Suite) Type() string {
	return schnorr.SchnorrSr25519Type
}

func (s *SchnorrSr25519Suite) GeneratePrivateKey() (key.PrivateKey, error) {
	return GenerateSchnorrSr25519PrivateKey()
}

func (s *SchnorrSr25519Suite) PrivateKeyFromBytes(data []byte) (key.PrivateKey, error) {
	return SchnorrSr25519PrivateKeyFromBytes(data)
}

func (s *SchnorrSr25519Suite) PublicKeyFromBytes(data []byte) (key.PublicKey, error) {
	return SchnorrSr25519PublicKeyFromBytes(data)
}

func (s *SchnorrSr25519Suite) SignatureFromBytes(data []byte) (key.Signature, error) {
	return SchnorrSr25519SignatureFromBytes(data)
}
