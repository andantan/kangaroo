package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	eddsaformat "github.com/andantan/kangaroo/crypto/eddsa"
	"strings"
)

type EdDSAEd25519PrivateKey struct {
	key ed25519.PrivateKey
}

var _ crypto.PrivateKey = (*EdDSAEd25519PrivateKey)(nil)

func (k *EdDSAEd25519PrivateKey) Bytes() []byte {
	return append([]byte(nil), k.key...)
}

func (k *EdDSAEd25519PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd25519PrivateKey) IsValid() bool {
	return len(k.key) == ed25519.PrivateKeySize
}

func (k *EdDSAEd25519PrivateKey) Type() string {
	return eddsaformat.EdDSAEd25519Type
}

func (k *EdDSAEd25519PrivateKey) PublicKey() crypto.PublicKey {
	pk := k.key.Public().(ed25519.PublicKey)
	return &EdDSAEd25519PublicKey{
		Key: pk,
	}
}

func (k *EdDSAEd25519PrivateKey) Sign(data []byte) (crypto.Signature, error) {
	sig := ed25519.Sign(k.key, data)
	point := [32]byte{}
	scalar := [32]byte{}

	copy(point[:], sig[:32])
	copy(scalar[:], sig[32:])

	return &EdDSAEd25519Signature{
		Point:  point,
		Scalar: scalar,
	}, nil
}

func GenerateEdDSAEd25519PrivateKey() (crypto.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &EdDSAEd25519PrivateKey{
		key: k,
	}, nil
}

func EdDSAEd25519PrivateKeyFromBytes(b []byte) (crypto.PrivateKey, error) {
	if len(b) != eddsaformat.EdDSAPrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", eddsaformat.EdDSAEd25519Type, eddsaformat.EdDSAPrivateKeyBytesLength, len(b))
	}

	return &EdDSAEd25519PrivateKey{
		key: b,
	}, nil
}

func EdDSAEd25519PrivateKeyFromString(s string) (crypto.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != eddsaformat.EdDSAPrivateKeyHexLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", eddsaformat.EdDSAEd25519Type, eddsaformat.EdDSAPrivateKeyHexLength, len(s))
	}

	privKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return EdDSAEd25519PrivateKeyFromBytes(privKeyBytes)
}
