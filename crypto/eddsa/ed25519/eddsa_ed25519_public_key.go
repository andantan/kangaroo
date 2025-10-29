package ed25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	eddsaformat "github.com/andantan/kangaroo/crypto/eddsa"
	"github.com/andantan/kangaroo/types"
	"strings"
)

type EdDSAEd25519PublicKey struct {
	Key []byte
}

var _ crypto.PublicKey = (*EdDSAEd25519PublicKey)(nil)

func (k *EdDSAEd25519PublicKey) Bytes() []byte {
	return append([]byte(nil), k.Key...)
}

func (k *EdDSAEd25519PublicKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd25519PublicKey) IsValid() bool {
	if k.Key == nil || len(k.Key) != eddsaformat.EdDSAPublicKeyBytesLength {
		return false
	}

	return true
}

func (k *EdDSAEd25519PublicKey) Type() string {
	return eddsaformat.EdDSAEd25519Type
}

func (k *EdDSAEd25519PublicKey) Equal(other crypto.PublicKey) bool {
	if k == nil || other == nil {
		return false
	}

	otherKey, ok := other.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	return bytes.Equal(k.Bytes(), otherKey.Bytes())
}

func (k *EdDSAEd25519PublicKey) Address(deriver types.AddressDeriver) types.Addressable {
	return deriver.Derive(k.Key)
}

func EdDSAEd25519PublicKeyFromBytes(b []byte) (crypto.PublicKey, error) {
	if len(b) != eddsaformat.EdDSAPublicKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for public-key<%s>: expected %d, got %d", eddsaformat.EdDSAEd25519Type, eddsaformat.EdDSAPublicKeyBytesLength, len(b))
	}

	keyBytes := append([]byte(nil), b...)
	return &EdDSAEd25519PublicKey{
		Key: keyBytes,
	}, nil
}

func EdDSAEd25519PublicKeyFromString(s string) (crypto.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != eddsaformat.EdDSAPublicKeyHexLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", eddsaformat.EdDSAEd25519Type, eddsaformat.EdDSAPublicKeyHexLength, len(s))
	}

	pubkeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return EdDSAEd25519PublicKeyFromBytes(pubkeyBytes)
}
