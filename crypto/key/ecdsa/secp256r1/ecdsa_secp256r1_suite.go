package secp256r1

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterKeySuite(&ECDSASecp256r1Suite{})
}

type ECDSASecp256r1Suite struct{}

var _ key.KeySuite = (*ECDSASecp256r1Suite)(nil)

func (s *ECDSASecp256r1Suite) Type() string {
	return ecdsa.ECDSASecp256r1Type
}

func (s *ECDSASecp256r1Suite) GeneratePrivateKey() (key.PrivateKey, error) {
	return GenerateECDSASecp256r1PrivateKey()
}

func (s *ECDSASecp256r1Suite) PrivateKeyFromBytes(data []byte) (key.PrivateKey, error) {
	return ECDSASecp256r1PrivateKeyFromBytes(data)
}

func (s *ECDSASecp256r1Suite) PublicKeyFromBytes(data []byte) (key.PublicKey, error) {
	return ECDSASecp256r1PublicKeyFromBytes(data)
}

func (s *ECDSASecp256r1Suite) SignatureFromBytes(data []byte) (key.Signature, error) {
	return ECDSASecp256r1SignatureFromBytes(data)
}
