package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooschnorr "github.com/andantan/kangaroo/crypto/key/schnorr"
	dcrschnorr "github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

type SchnorrSecp256k1PublicKey struct {
	Key []byte
}

var _ key.PublicKey = (*SchnorrSecp256k1PublicKey)(nil)

func SchnorrSecp256k1PublicKeyFromBytes(b []byte) (key.PublicKey, error) {
	if len(b) != kangarooschnorr.SchnorrSecp256k1PublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d",
			kangarooschnorr.SchnorrSecp256k1Type, kangarooschnorr.SchnorrSecp256k1PublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	k := &SchnorrSecp256k1PublicKey{
		Key: keyBytes,
	}

	if !k.IsValid() {
		return nil, fmt.Errorf("public key is not a valid point on schnorr-secp256k1 curve")
	}

	return k, nil
}

func (k *SchnorrSecp256k1PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *SchnorrSecp256k1PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *SchnorrSecp256k1PublicKey) ShortString(length int) string {
	ks := hex.EncodeToString(k.Bytes())
	if length > len(ks) {
		length = len(ks)
	}
	return "0x" + ks[:length]
}

func (k *SchnorrSecp256k1PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != kangarooschnorr.SchnorrSecp256k1PublicKeyBytesLength {
		return false
	}

	_, err := dcrschnorr.ParsePubKey(k.Key)
	return err == nil
}

func (k *SchnorrSecp256k1PublicKey) Type() string {
	return kangarooschnorr.SchnorrSecp256k1Type
}

func (k *SchnorrSecp256k1PublicKey) Equal(other key.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*SchnorrSecp256k1PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *SchnorrSecp256k1PublicKey) Address(deriver hash.AddressDeriver) hash.Address {
	return deriver.Derive(k.Key)
}
