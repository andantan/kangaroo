package secp256k1

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterKeySuite(&ECDSASecp256k1Suite{})
}

type ECDSASecp256k1Suite struct{}

var _ key.KeySuite = (*ECDSASecp256k1Suite)(nil)

func (s *ECDSASecp256k1Suite) Type() string {
	return ecdsa.ECDSASecp256k1Type
}

func (s *ECDSASecp256k1Suite) GeneratePrivateKey() (key.PrivateKey, error) {
	return GenerateECDSASecp256k1PrivateKey()
}

func (s *ECDSASecp256k1Suite) PrivateKeyFromBytes(data []byte) (key.PrivateKey, error) {
	return ECDSASecp256k1PrivateKeyFromBytes(data)
}

func (s *ECDSASecp256k1Suite) PublicKeyFromBytes(data []byte) (key.PublicKey, error) {
	return ECDSASecp256k1PublicKeyFromBytes(data)
}

func (s *ECDSASecp256k1Suite) SignatureFromBytes(data []byte) (key.Signature, error) {
	return ECDSASecp256k1SignatureFromBytes(data)
}
