package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
)

type EdDSAEd25519PrivateKey struct {
	key ed25519.PrivateKey
}

var _ key.PrivateKey = (*EdDSAEd25519PrivateKey)(nil)

func GenerateEdDSAEd25519PrivateKey() (key.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &EdDSAEd25519PrivateKey{
		key: k,
	}, nil
}

func EdDSAEd25519PrivateKeyFromBytes(b []byte) (key.PrivateKey, error) {
	if len(b) != eddsa.EdDSAEd25519PrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d",
			eddsa.EdDSAEd25519Type, eddsa.EdDSAEd25519PrivateKeyBytesLength, len(b))
	}

	return &EdDSAEd25519PrivateKey{
		key: b,
	}, nil
}

func (k *EdDSAEd25519PrivateKey) Bytes() []byte {
	return k.key[:]
}

func (k *EdDSAEd25519PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd25519PrivateKey) IsValid() bool {
	return len(k.key) == eddsa.EdDSAEd25519PrivateKeyBytesLength
}

func (k *EdDSAEd25519PrivateKey) Type() string {
	return eddsa.EdDSAEd25519Type
}

func (k *EdDSAEd25519PrivateKey) PublicKey() key.PublicKey {
	pk := k.key.Public().(ed25519.PublicKey)
	return &EdDSAEd25519PublicKey{
		Key: pk,
	}
}

func (k *EdDSAEd25519PrivateKey) Sign(data []byte) (key.Signature, error) {
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
