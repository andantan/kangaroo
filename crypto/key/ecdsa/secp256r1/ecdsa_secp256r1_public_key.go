package secp256r1

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/andantan/kangaroo/crypto/registry"
)

type ECDSASecp256r1PublicKey struct {
	Key []byte
}

var _ kangarookey.PublicKey = (*ECDSASecp256r1PublicKey)(nil)

func (k *ECDSASecp256r1PublicKey) Bytes() []byte {
	prefix, err := registry.GetKeyPrefixFromType(k.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration public-key<%s> panic: %v", k.Type(), err))
	}

	return append([]byte{prefix}, k.Key...)
}

func (k *ECDSASecp256r1PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256r1PublicKey) IsValid() bool {
	if k == nil || len(k.Key) != kangarooecdsa.ECDSAPublicKeyBytesLength {
		return false
	}

	x, _ := elliptic.UnmarshalCompressed(defaultCurve, k.Key)
	return x != nil
}

func (k *ECDSASecp256r1PublicKey) Type() string {
	return kangarooecdsa.ECDSASecp256r1Type
}

func (k *ECDSASecp256r1PublicKey) Equal(other kangarookey.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSASecp256r1PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Key, otherKey.Key)
}

func (k *ECDSASecp256r1PublicKey) Address(deriver kangaroohash.AddressDeriver) kangaroohash.Address {
	return deriver.Derive(k.Key)
}

func ECDSASecp256r1PublicKeyFromBytes(b []byte) (kangarookey.PublicKey, error) {
	if len(b) != kangarooecdsa.ECDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256r1Type, kangarooecdsa.ECDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	k := &ECDSASecp256r1PublicKey{
		Key: keyBytes,
	}

	if !k.IsValid() {
		return nil, fmt.Errorf("public key is not a valid point on ecdsa-secp256r1 curve")
	}

	return k, nil
}
