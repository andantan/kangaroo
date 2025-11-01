package ed25519

import (
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterKeySuite(&EdDSAEd25519Suite{})
}

type EdDSAEd25519Suite struct{}

var _ kangarookey.KeySuite = (*EdDSAEd25519Suite)(nil)

func (s *EdDSAEd25519Suite) Type() string {
	return kangarooeddsa.EdDSAEd25519Type
}

func (s *EdDSAEd25519Suite) GeneratePrivateKey() (kangarookey.PrivateKey, error) {
	return GenerateEdDSAEd25519PrivateKey()
}

func (s *EdDSAEd25519Suite) PrivateKeyFromBytes(data []byte) (kangarookey.PrivateKey, error) {
	return EdDSAEd25519PrivateKeyFromBytes(data)
}

func (s *EdDSAEd25519Suite) PublicKeyFromBytes(data []byte) (kangarookey.PublicKey, error) {
	return EdDSAEd25519PublicKeyFromBytes(data)
}

func (s *EdDSAEd25519Suite) SignatureFromBytes(data []byte) (kangarookey.Signature, error) {
	return EdDSAEd25519SignatureFromBytes(data)
}
