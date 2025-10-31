package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strings"
)

type ECDSASecp256k1PublicKey struct {
	Key []byte
}

var _ kangarookey.PublicKey = (*ECDSASecp256k1PublicKey)(nil)

func (k *ECDSASecp256k1PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *ECDSASecp256k1PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256k1PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != kangarooecdsa.ECDSAPublicKeyBytesLength {
		return false
	}

	_, err := secp256k1.ParsePubKey(k.Key)

	return err == nil
}

func (k *ECDSASecp256k1PublicKey) Type() string {
	return kangarooecdsa.ECDSASecp256k1Type
}

func (k *ECDSASecp256k1PublicKey) Equal(other kangarookey.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSASecp256k1PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *ECDSASecp256k1PublicKey) Address(deriver kangaroohash.AddressDeriver) kangaroohash.Address {
	return deriver.Derive(k.Key)
}

func ECDSASecp256k1PublicKeyFromBytes(b []byte) (kangarookey.PublicKey, error) {
	if len(b) != kangarooecdsa.ECDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256k1Type, kangarooecdsa.ECDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	k := &ECDSASecp256k1PublicKey{
		Key: keyBytes,
	}

	if !k.IsValid() {
		return nil, fmt.Errorf("public key is not a valid point on ecdsa-secp256k1 curve")
	}

	return k, nil
}

func ECDSASecp256k1PublicKeyFromString(s string) (kangarookey.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangarooecdsa.ECDSAPublicKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for public-key<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256k1Type, kangarooecdsa.ECDSAPublicKeyHexLength, len(s))
	}

	pubKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSASecp256k1PublicKeyFromBytes(pubKeyBytes)
}
