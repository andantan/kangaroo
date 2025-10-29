package p256

import (
	kangaroocrypto "github.com/andantan/kangaroo/crypto"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
)

func init() {
	kangaroocrypto.RegisterKeySuite(&ECDSAP256Suite{})
}

type ECDSAP256Suite struct{}

var _ kangarookey.KeySuite = (*ECDSAP256Suite)(nil)

func (s *ECDSAP256Suite) Type() string {
	return kangarooecdsa.ECDSAP256Type
}

func (s *ECDSAP256Suite) GeneratePrivateKey() (kangarookey.PrivateKey, error) {
	return GenerateECDSAP256PrivateKey()
}

func (s *ECDSAP256Suite) PrivateKeyFromBytes(data []byte) (kangarookey.PrivateKey, error) {
	return ECDSAP256PrivateKeyFromBytes(data)
}

func (s *ECDSAP256Suite) PublicKeyFromBytes(data []byte) (kangarookey.PublicKey, error) {
	return ECDSAP256PublicKeyFromBytes(data)
}

func (s *ECDSAP256Suite) SignatureFromBytes(data []byte) (kangarookey.Signature, error) {
	return ECDSAP256SignatureFromBytes(data)
}
