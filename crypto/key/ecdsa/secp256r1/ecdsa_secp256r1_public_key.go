package secp256r1

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
)

type ECDSASecp256r1PublicKey struct {
	Key []byte
}

var _ key.PublicKey = (*ECDSASecp256r1PublicKey)(nil)

func (k *ECDSASecp256r1PublicKey) Bytes() []byte {
	return k.Key[:]
}

func (k *ECDSASecp256r1PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256r1PublicKey) ShortString(length int) string {
	ks := hex.EncodeToString(k.Bytes())
	if length > len(ks) {
		length = len(ks)
	}
	return "0x" + ks[:length]
}

func (k *ECDSASecp256r1PublicKey) IsValid() bool {
	if k == nil || len(k.Key) != ecdsa.ECDSASecp256r1PublicKeyBytesLength {
		return false
	}

	x, _ := elliptic.UnmarshalCompressed(defaultCurve, k.Key)
	return x != nil
}

func (k *ECDSASecp256r1PublicKey) Type() string {
	return ecdsa.ECDSASecp256r1Type
}

func (k *ECDSASecp256r1PublicKey) Equal(other key.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSASecp256r1PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Key, otherKey.Key)
}

func (k *ECDSASecp256r1PublicKey) Address(deriver hash.AddressDeriver) hash.Address {
	return deriver.Derive(k.Key)
}

func ECDSASecp256r1PublicKeyFromBytes(b []byte) (key.PublicKey, error) {
	if len(b) != ecdsa.ECDSASecp256r1PublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", ecdsa.ECDSASecp256r1Type, ecdsa.ECDSASecp256r1PublicKeyBytesLength, len(b))
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
