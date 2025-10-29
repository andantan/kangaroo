package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	ecdsaformat "github.com/andantan/kangaroo/crypto/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"strings"
)

type ECDSASecp256k1PrivateKey struct {
	key *secp256k1.PrivateKey
}

var _ crypto.PrivateKey = (*ECDSASecp256k1PrivateKey)(nil)

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
	return ecdsaformat.ECDSASecp256k1Type
}

func (k *ECDSASecp256k1PrivateKey) PublicKey() crypto.PublicKey {
	pk := k.key.PubKey()
	return &ECDSASecp256k1PublicKey{
		Key: pk.SerializeCompressed(),
	}
}

func (k *ECDSASecp256k1PrivateKey) Sign(data []byte) (crypto.Signature, error) {
	sig := ecdsa.Sign(k.key, data)
	r := sig.R()
	s := sig.S()

	return &ECDSASecp256k1Signature{
		R: &r,
		S: &s,
	}, nil
}

func GenerateECDSASecp256k1PrivateKey() (crypto.PrivateKey, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &ECDSASecp256k1PrivateKey{
		key: k,
	}, nil
}

func ECDSASecp256k1PrivateKeyFromBytes(b []byte) (crypto.PrivateKey, error) {
	if len(b) != ecdsaformat.ECDSAPrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", ecdsaformat.ECDSASecp256k1Type, ecdsaformat.ECDSAPrivateKeyBytesLength, len(b))
	}

	pk := secp256k1.PrivKeyFromBytes(b)

	return &ECDSASecp256k1PrivateKey{
		key: pk,
	}, nil
}

func ECDSASecp256k1PrivateKeyFromString(s string) (crypto.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != ecdsaformat.ECDSAPrivateKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for private-key<%s>: expected %d, got %d", ecdsaformat.ECDSASecp256k1Type, len(s), ecdsaformat.ECDSAPrivateKeyHexLength)
	}

	privKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSASecp256k1PrivateKeyFromBytes(privKeyBytes)
}
