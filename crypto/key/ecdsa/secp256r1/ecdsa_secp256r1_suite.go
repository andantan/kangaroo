package secp256r1

import (
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterKeySuite(&ECDSASecp256r1Suite{})
}

type ECDSASecp256r1Suite struct{}

var _ kangarookey.KeySuite = (*ECDSASecp256r1Suite)(nil)

func (s *ECDSASecp256r1Suite) Type() string {
	return kangarooecdsa.ECDSASecp256r1Type
}

func (s *ECDSASecp256r1Suite) GeneratePrivateKey() (kangarookey.PrivateKey, error) {
	return GenerateECDSASecp256r1PrivateKey()
}

func (s *ECDSASecp256r1Suite) PrivateKeyFromBytes(data []byte) (kangarookey.PrivateKey, error) {
	return ECDSASecp256r1PrivateKeyFromBytes(data)
}

func (s *ECDSASecp256r1Suite) PublicKeyFromBytes(data []byte) (kangarookey.PublicKey, error) {
	return ECDSASecp256r1PublicKeyFromBytes(data)
}

func (s *ECDSASecp256r1Suite) SignatureFromBytes(data []byte) (kangarookey.Signature, error) {
	return ECDSASecp256r1SignatureFromBytes(data)
}
