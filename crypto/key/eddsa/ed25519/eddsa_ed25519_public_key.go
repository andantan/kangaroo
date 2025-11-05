package ed25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
)

type EdDSAEd25519PublicKey struct {
	Key []byte
}

var _ key.PublicKey = (*EdDSAEd25519PublicKey)(nil)

func EdDSAEd25519PublicKeyFromBytes(b []byte) (key.PublicKey, error) {
	if len(b) != eddsa.EdDSAEd25519PublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", eddsa.EdDSAEd25519Type, eddsa.EdDSAEd25519PublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	return &EdDSAEd25519PublicKey{
		Key: keyBytes,
	}, nil
}

func (k *EdDSAEd25519PublicKey) Bytes() []byte {
	return k.Key[:]
}

func (k *EdDSAEd25519PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd25519PublicKey) IsValid() bool {
	// This performs a length check. Full cryptographic validation of the point
	// is implicitly handled by the ed25519.Verify function.
	if k.Key == nil || len(k.Key) != eddsa.EdDSAEd25519PublicKeyBytesLength {
		return false
	}

	return true
}

func (k *EdDSAEd25519PublicKey) Type() string {
	return eddsa.EdDSAEd25519Type
}

func (k *EdDSAEd25519PublicKey) Equal(other key.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *EdDSAEd25519PublicKey) Address(deriver hash.AddressDeriver) hash.Address {
	return deriver.Derive(k.Key)
}
