package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ECDSASecp256k1PublicKey struct {
	Key []byte
}

var _ key.PublicKey = (*ECDSASecp256k1PublicKey)(nil)

func (k *ECDSASecp256k1PublicKey) Bytes() []byte {
	return k.Key[:]
}

func (k *ECDSASecp256k1PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256k1PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != ecdsa.ECDSASecp256k1PublicKeyBytesLength {
		return false
	}

	_, err := secp256k1.ParsePubKey(k.Key)

	return err == nil
}

func (k *ECDSASecp256k1PublicKey) Type() string {
	return ecdsa.ECDSASecp256k1Type
}

func (k *ECDSASecp256k1PublicKey) Equal(other key.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*ECDSASecp256k1PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *ECDSASecp256k1PublicKey) Address(deriver hash.AddressDeriver) hash.Address {
	return deriver.Derive(k.Key)
}

func ECDSASecp256k1PublicKeyFromBytes(b []byte) (key.PublicKey, error) {
	if len(b) != ecdsa.ECDSASecp256k1PublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d",
			ecdsa.ECDSASecp256k1Type, ecdsa.ECDSASecp256k1PublicKeyBytesLength, len(b))
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
