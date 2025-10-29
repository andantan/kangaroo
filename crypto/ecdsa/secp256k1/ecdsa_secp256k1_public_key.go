package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	ecdsaformat "github.com/andantan/kangaroo/crypto/ecdsa"
	"github.com/andantan/kangaroo/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strings"
)

type ECDSASecp256k1PublicKey struct {
	Key []byte
}

var _ crypto.PublicKey = (*ECDSASecp256k1PublicKey)(nil)

func (k *ECDSASecp256k1PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *ECDSASecp256k1PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256k1PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != ecdsaformat.ECDSAPublicKeyBytesLength {
		return false
	}

	_, err := secp256k1.ParsePubKey(k.Key)

	return err == nil
}

func (k *ECDSASecp256k1PublicKey) Type() string {
	return ecdsaformat.ECDSASecp256k1Type
}

func (k *ECDSASecp256k1PublicKey) Equal(other crypto.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSASecp256k1PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *ECDSASecp256k1PublicKey) Address(deriver types.AddressDeriver) types.Addressable {
	return deriver.Derive(k.Key)
}

func ECDSASecp256k1PublicKeyFromBytes(b []byte) (crypto.PublicKey, error) {
	if len(b) != ecdsaformat.ECDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", ecdsaformat.ECDSASecp256k1Type, ecdsaformat.ECDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	key := &ECDSASecp256k1PublicKey{
		Key: keyBytes,
	}

	if !key.IsValid() {
		return nil, fmt.Errorf("public key is not a valid point on ecdsa-secp256k1 curve")
	}

	return key, nil
}

func ECDSASecp256k1PublicKeyFromString(s string) (crypto.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != ecdsaformat.ECDSAPublicKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for public-key<%s>: expected %d, got %d", ecdsaformat.ECDSASecp256k1Type, ecdsaformat.ECDSAPublicKeyHexLength, len(s))
	}

	pubKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSASecp256k1PublicKeyFromBytes(pubKeyBytes)
}
