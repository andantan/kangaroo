package ed448

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
)

type EdDSAEd448PublicKey struct {
	Key []byte
}

var _ key.PublicKey = (*EdDSAEd448PublicKey)(nil)

func EdDSAEd448PublicKeyFromBytes(b []byte) (key.PublicKey, error) {
	if len(b) != eddsa.EdDSAEd448PublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d",
			eddsa.EdDSAEd448Type, eddsa.EdDSAEd448PublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	return &EdDSAEd448PublicKey{
		Key: keyBytes,
	}, nil
}

func (k *EdDSAEd448PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *EdDSAEd448PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd448PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != eddsa.EdDSAEd448PublicKeyBytesLength {
		return false
	}

	return true
}

func (k *EdDSAEd448PublicKey) Type() string {
	return eddsa.EdDSAEd448Type
}

func (k *EdDSAEd448PublicKey) Equal(other key.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*EdDSAEd448PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *EdDSAEd448PublicKey) Address(deriver hash.AddressDeriver) hash.Address {
	return deriver.Derive(k.Key)
}
