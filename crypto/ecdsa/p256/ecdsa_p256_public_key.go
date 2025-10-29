package p256

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	ecdsaformat "github.com/andantan/kangaroo/crypto/ecdsa"
	"github.com/andantan/kangaroo/types"
	"strings"
)

type ECDSAP256PublicKey struct {
	Key []byte
}

var _ crypto.PublicKey = (*ECDSAP256PublicKey)(nil)

func (k *ECDSAP256PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *ECDSAP256PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Key)
}

func (k *ECDSAP256PublicKey) IsValid() bool {
	if k == nil || len(k.Key) != ecdsaformat.ECDSAPublicKeyBytesLength {
		return false
	}

	x, _ := elliptic.UnmarshalCompressed(defaultCurve, k.Key)
	return x != nil
}

func (k *ECDSAP256PublicKey) Type() string {
	return ecdsaformat.ECDSAP256Type
}

func (k *ECDSAP256PublicKey) Equal(other crypto.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSAP256PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Key, otherKey.Key)
}

func (k *ECDSAP256PublicKey) Address(deriver types.AddressDeriver) types.Addressable {
	return deriver.Derive(k.Key)
}

func ECDSAP256PublicKeyFromBytes(b []byte) (crypto.PublicKey, error) {
	if len(b) != ecdsaformat.ECDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", ecdsaformat.ECDSAP256Type, ecdsaformat.ECDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	key := &ECDSAP256PublicKey{
		Key: keyBytes,
	}

	if !key.IsValid() {
		return nil, fmt.Errorf("public key is not a valid point on ecdsa-p256 curve")
	}

	return key, nil
}

func ECDSAP256PublicKeyFromString(s string) (crypto.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != ecdsaformat.ECDSAPublicKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for public-key<%s>: expected %d, got %d", ecdsaformat.ECDSAP256Type, ecdsaformat.ECDSAPublicKeyHexLength, len(s))
	}

	pubKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSAP256PublicKeyFromBytes(pubKeyBytes)
}
