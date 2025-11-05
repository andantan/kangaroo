package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type ECDSASecp256k1PrivateKey struct {
	key *secp256k1.PrivateKey
}

var _ key.PrivateKey = (*ECDSASecp256k1PrivateKey)(nil)

func GenerateECDSASecp256k1PrivateKey() (key.PrivateKey, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &ECDSASecp256k1PrivateKey{
		key: k,
	}, nil
}

func ECDSASecp256k1PrivateKeyFromBytes(b []byte) (key.PrivateKey, error) {
	if len(b) != kangarooecdsa.ECDSASecp256k1PrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d",
			kangarooecdsa.ECDSASecp256k1Type, kangarooecdsa.ECDSASecp256k1PrivateKeyBytesLength, len(b))
	}

	pk := secp256k1.PrivKeyFromBytes(b)

	return &ECDSASecp256k1PrivateKey{
		key: pk,
	}, nil
}

func (k *ECDSASecp256k1PrivateKey) Bytes() []byte {
	return k.key.Serialize()
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

func (k *ECDSASecp256k1PrivateKey) PublicKey() key.PublicKey {
	pk := k.key.PubKey()
	return &ECDSASecp256k1PublicKey{
		Key: pk.SerializeCompressed(),
	}
}

func (k *ECDSASecp256k1PrivateKey) Sign(data []byte) (key.Signature, error) {
	sig := dcrecdsa.Sign(k.key, data)
	r := sig.R()
	s := sig.S()

	return &ECDSASecp256k1Signature{
		R: &r,
		S: &s,
	}, nil
}
