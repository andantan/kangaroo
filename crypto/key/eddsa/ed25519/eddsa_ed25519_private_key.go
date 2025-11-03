package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

type EdDSAEd25519PrivateKey struct {
	key ed25519.PrivateKey
}

var _ kangarookey.PrivateKey = (*EdDSAEd25519PrivateKey)(nil)

func (k *EdDSAEd25519PrivateKey) Bytes() []byte {
	prefix, err := kangarooregistry.GetKeyPrefixFromType(k.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration private-key<%s> panic: %v", k.Type(), err))
	}
	return append([]byte{prefix}, k.key...)
}

func (k *EdDSAEd25519PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd25519PrivateKey) IsValid() bool {
	return len(k.key) == ed25519.PrivateKeySize
}

func (k *EdDSAEd25519PrivateKey) Type() string {
	return kangarooeddsa.EdDSAEd25519Type
}

func (k *EdDSAEd25519PrivateKey) PublicKey() kangarookey.PublicKey {
	pk := k.key.Public().(ed25519.PublicKey)
	return &EdDSAEd25519PublicKey{
		Key: pk,
	}
}

func (k *EdDSAEd25519PrivateKey) Sign(data []byte) (kangarookey.Signature, error) {
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

func GenerateEdDSAEd25519PrivateKey() (kangarookey.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &EdDSAEd25519PrivateKey{
		key: k,
	}, nil
}

func EdDSAEd25519PrivateKeyFromBytes(b []byte) (kangarookey.PrivateKey, error) {
	if len(b) != kangarooeddsa.EdDSAPrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", kangarooeddsa.EdDSAEd25519Type, kangarooeddsa.EdDSAPrivateKeyBytesLength, len(b))
	}

	return &EdDSAEd25519PrivateKey{
		key: b,
	}, nil
}
