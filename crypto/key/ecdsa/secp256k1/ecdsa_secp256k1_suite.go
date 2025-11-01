package secp256k1

import (
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterKeySuite(&ECDSASecp256k1Suite{})
}

type ECDSASecp256k1Suite struct{}

var _ kangarookey.KeySuite = (*ECDSASecp256k1Suite)(nil)

func (s *ECDSASecp256k1Suite) Type() string {
	return kangarooecdsa.ECDSASecp256k1Type
}

func (s *ECDSASecp256k1Suite) GeneratePrivateKey() (kangarookey.PrivateKey, error) {
	return GenerateECDSASecp256k1PrivateKey()
}

func (s *ECDSASecp256k1Suite) PrivateKeyFromBytes(data []byte) (kangarookey.PrivateKey, error) {
	return ECDSASecp256k1PrivateKeyFromBytes(data)
}

func (s *ECDSASecp256k1Suite) PublicKeyFromBytes(data []byte) (kangarookey.PublicKey, error) {
	return ECDSASecp256k1PublicKeyFromBytes(data)
}

func (s *ECDSASecp256k1Suite) SignatureFromBytes(data []byte) (kangarookey.Signature, error) {
	return ECDSASecp256k1SignatureFromBytes(data)
}
