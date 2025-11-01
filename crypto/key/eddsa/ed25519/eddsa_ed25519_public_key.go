package ed25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/andantan/kangaroo/crypto/registry"
)

type EdDSAEd25519PublicKey struct {
	Key []byte
}

var _ kangarookey.PublicKey = (*EdDSAEd25519PublicKey)(nil)

func (k *EdDSAEd25519PublicKey) Bytes() []byte {
	prefix, err := registry.GetPrefixFromType(k.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration public-key<%s> panic: %v", k.Type(), err))
	}
	return append([]byte{prefix}, k.Key...)
}

func (k *EdDSAEd25519PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd25519PublicKey) IsValid() bool {
	// This performs a length check. Full cryptographic validation of the point
	// is implicitly handled by the ed25519.Verify function.
	if k.Key == nil || len(k.Key) != kangarooeddsa.EdDSAPublicKeyBytesLength {
		return false
	}

	return true
}

func (k *EdDSAEd25519PublicKey) Type() string {
	return kangarooeddsa.EdDSAEd25519Type
}

func (k *EdDSAEd25519PublicKey) Equal(other kangarookey.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *EdDSAEd25519PublicKey) Address(deriver kangaroohash.AddressDeriver) kangaroohash.Address {
	return deriver.Derive(k.Key)
}

func EdDSAEd25519PublicKeyFromBytes(b []byte) (kangarookey.PublicKey, error) {
	if len(b) != kangarooeddsa.EdDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", kangarooeddsa.EdDSAEd25519Type, kangarooeddsa.EdDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	return &EdDSAEd25519PublicKey{
		Key: keyBytes,
	}, nil
}
