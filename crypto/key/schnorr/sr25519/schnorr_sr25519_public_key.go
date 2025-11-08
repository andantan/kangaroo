package sr25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
)

type SchnorrSr25519PublicKey struct {
	Key []byte
}

var _ key.PublicKey = (*SchnorrSr25519PublicKey)(nil)

func SchnorrSr25519PublicKeyFromBytes(b []byte) (key.PublicKey, error) {
	if len(b) != schnorr.SchnorrSr25519PublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d",
			schnorr.SchnorrSr25519Type, schnorr.SchnorrSr25519PublicKeyBytesLength, len(b))
	}

	a := [schnorr.SchnorrSr25519PublicKeyBytesLength]byte{}
	copy(a[:], b)

	if a == [schnorr.SchnorrSr25519PublicKeyBytesLength]byte{} {
		return nil, fmt.Errorf("empty given public key")
	}

	k := schnorrkel.PublicKey{}
	if err := k.Decode(a); err != nil {
		return nil, err
	}

	kb := k.Encode()
	return &SchnorrSr25519PublicKey{
		Key: kb[:],
	}, nil
}

func (k *SchnorrSr25519PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *SchnorrSr25519PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *SchnorrSr25519PublicKey) ShortString(length int) string {
	ks := hex.EncodeToString(k.Bytes())
	if length > len(ks) {
		length = len(ks)
	}
	return "0x" + ks[:length]
}

func (k *SchnorrSr25519PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != schnorr.SchnorrSr25519PublicKeyBytesLength {
		return false
	}

	a := [schnorr.SchnorrSr25519PublicKeyBytesLength]byte{}
	copy(a[:], k.Key)
	pk := &schnorrkel.PublicKey{}
	err := pk.Decode(a)
	return err == nil
}

func (k *SchnorrSr25519PublicKey) Type() string {
	return schnorr.SchnorrSr25519Type
}

func (k *SchnorrSr25519PublicKey) Equal(other key.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*SchnorrSr25519PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *SchnorrSr25519PublicKey) Address(deriver hash.AddressDeriver) hash.Address {
	return deriver.Derive(k.Key)
}
