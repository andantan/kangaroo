package secp256k1

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterKeySuite(&SchnorrSecp256k1Suite{})
}

type SchnorrSecp256k1Suite struct{}

var _ key.KeySuite = (*SchnorrSecp256k1Suite)(nil)

func (s *SchnorrSecp256k1Suite) Type() string {
	return schnorr.SchnorrSecp256k1Type
}

func (s *SchnorrSecp256k1Suite) GeneratePrivateKey() (key.PrivateKey, error) {
	return GenerateSchnorrSecp256k1PrivateKey()
}

func (s *SchnorrSecp256k1Suite) PrivateKeyFromBytes(data []byte) (key.PrivateKey, error) {
	return SchnorrSecp256k1PrivateKeyFromBytes(data)
}

func (s *SchnorrSecp256k1Suite) PublicKeyFromBytes(data []byte) (key.PublicKey, error) {
	return SchnorrSecp256k1PublicKeyFromBytes(data)
}

func (s *SchnorrSecp256k1Suite) SignatureFromBytes(data []byte) (key.Signature, error) {
	return SchnorrSecp256k1SignatureFromBytes(data)
}
