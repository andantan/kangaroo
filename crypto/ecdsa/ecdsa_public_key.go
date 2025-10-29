package ecdsa

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	"github.com/andantan/kangaroo/types"
	"strings"
)

const (
	// PublicKeyLength Standard length of a P256 compressed public key
	PublicKeyLength    = 33
	PublicKeyHexLength = PublicKeyLength * 2
)

type ECDSAPublicKey struct {
	Key []byte
}

var _ crypto.PublicKey = (*ECDSAPublicKey)(nil)

func (k *ECDSAPublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *ECDSAPublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Key)
}

func (k *ECDSAPublicKey) IsValid() bool {
	if k == nil || len(k.Key) != PublicKeyLength {
		return false
	}

	x, _ := elliptic.UnmarshalCompressed(defaultCurve, k.Key)
	return x != nil
}

func (k *ECDSAPublicKey) Type() string {
	return ECDSAP256Type
}

func (k *ECDSAPublicKey) Equal(other crypto.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSAPublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Key, otherKey.Key)
}

func (k *ECDSAPublicKey) Address(deriver types.AddressDeriver) types.Addressable {
	return deriver.Derive(k.Key)
}

func ECDSAPublicKeyFromBytes(b []byte) (crypto.PublicKey, error) {
	if len(b) != PublicKeyLength {
		return nil, fmt.Errorf("invalid public key length: expected %d, got %d", PublicKeyLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	return &ECDSAPublicKey{
		Key: keyBytes,
	}, nil
}

func ECDSAPublicKeyFromString(s string) (crypto.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != PublicKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for public-key<%s> (%d), must be %d", ECDSAP256Type, len(s), PublicKeyHexLength)
	}

	pubKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSAPublicKeyFromBytes(pubKeyBytes)
}
