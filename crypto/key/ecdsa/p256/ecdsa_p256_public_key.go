package p256

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"strings"
)

type ECDSAP256PublicKey struct {
	Key []byte
}

var _ kangarookey.PublicKey = (*ECDSAP256PublicKey)(nil)

func (k *ECDSAP256PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *ECDSAP256PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Key)
}

func (k *ECDSAP256PublicKey) IsValid() bool {
	if k == nil || len(k.Key) != kangarooecdsa.ECDSAPublicKeyBytesLength {
		return false
	}

	x, _ := elliptic.UnmarshalCompressed(defaultCurve, k.Key)
	return x != nil
}

func (k *ECDSAP256PublicKey) Type() string {
	return kangarooecdsa.ECDSAP256Type
}

func (k *ECDSAP256PublicKey) Equal(other kangarookey.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSAP256PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Key, otherKey.Key)
}

func (k *ECDSAP256PublicKey) Address(deriver kangaroohash.AddressDeriver) kangaroohash.Addressable {
	return deriver.Derive(k.Key)
}

func ECDSAP256PublicKeyFromBytes(b []byte) (kangarookey.PublicKey, error) {
	if len(b) != kangarooecdsa.ECDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", kangarooecdsa.ECDSAP256Type, kangarooecdsa.ECDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	k := &ECDSAP256PublicKey{
		Key: keyBytes,
	}

	if !k.IsValid() {
		return nil, fmt.Errorf("public key is not a valid point on ecdsa-p256 curve")
	}

	return k, nil
}

func ECDSAP256PublicKeyFromString(s string) (kangarookey.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != kangarooecdsa.ECDSAPublicKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for public-key<%s>: expected %d, got %d", kangarooecdsa.ECDSAP256Type, kangarooecdsa.ECDSAPublicKeyHexLength, len(s))
	}

	pubKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSAP256PublicKeyFromBytes(pubKeyBytes)
}
