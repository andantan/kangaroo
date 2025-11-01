package secp256k1

import (
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type ECDSASecp256k1PrivateKey struct {
	key *secp256k1.PrivateKey
}

var _ kangarookey.PrivateKey = (*ECDSASecp256k1PrivateKey)(nil)

func (k *ECDSASecp256k1PrivateKey) Bytes() []byte {
	prefix, err := kangarooregistry.GetPrefixFromType(k.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration private-key<%s> panic: %v", k.Type(), err))
	}
	kb := k.key.Serialize()
	return append([]byte{prefix}, kb...)
}

func (k *ECDSASecp256k1PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256k1PrivateKey) IsValid() bool {
	if k == nil || k.key == nil {
		return false
	}

	return !k.key.Key.IsZero()
}

func (k *ECDSASecp256k1PrivateKey) Type() string {
	return kangarooecdsa.ECDSASecp256k1Type
}

func (k *ECDSASecp256k1PrivateKey) PublicKey() kangarookey.PublicKey {
	pk := k.key.PubKey()
	return &ECDSASecp256k1PublicKey{
		Key: pk.SerializeCompressed(),
	}
}

func (k *ECDSASecp256k1PrivateKey) Sign(data []byte) (kangarookey.Signature, error) {
	sig := ecdsa.Sign(k.key, data)
	r := sig.R()
	s := sig.S()

	return &ECDSASecp256k1Signature{
		R: &r,
		S: &s,
	}, nil
}

func GenerateECDSASecp256k1PrivateKey() (kangarookey.PrivateKey, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &ECDSASecp256k1PrivateKey{
		key: k,
	}, nil
}

func ECDSASecp256k1PrivateKeyFromBytes(b []byte) (kangarookey.PrivateKey, error) {
	if len(b) != kangarooecdsa.ECDSAPrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256k1Type, kangarooecdsa.ECDSAPrivateKeyBytesLength, len(b))
	}

	pk := secp256k1.PrivKeyFromBytes(b)

	return &ECDSASecp256k1PrivateKey{
		key: pk,
	}, nil
}
