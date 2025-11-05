package ed448

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/cloudflare/circl/sign/ed448"
)

type EdDSAEd448PrivateKey struct {
	key ed448.PrivateKey
}

var _ key.PrivateKey = (*EdDSAEd448PrivateKey)(nil)

func GenerateEdDSAEd448PrivateKey() (key.PrivateKey, error) {
	_, k, err := ed448.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &EdDSAEd448PrivateKey{
		key: k,
	}, nil
}

func EdDSAEd448PrivateKeyFromBytes(b []byte) (key.PrivateKey, error) {
	if len(b) != eddsa.EdDSAEd448PrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d",
			eddsa.EdDSAEd448Type, eddsa.EdDSAEd448PrivateKeyBytesLength, len(b))
	}

	return &EdDSAEd448PrivateKey{
		key: b,
	}, nil
}

func (k *EdDSAEd448PrivateKey) Bytes() []byte {
	return append([]byte(nil), k.key...)
}

func (k *EdDSAEd448PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *EdDSAEd448PrivateKey) IsValid() bool {
	return len(k.key) == eddsa.EdDSAEd448PrivateKeyBytesLength
}

func (k *EdDSAEd448PrivateKey) Type() string {
	return eddsa.EdDSAEd448Type
}

func (k *EdDSAEd448PrivateKey) PublicKey() key.PublicKey {
	pk := k.key.Public().(ed448.PublicKey)
	return &EdDSAEd448PublicKey{
		Key: pk,
	}
}

func (k *EdDSAEd448PrivateKey) Sign(data []byte) (key.Signature, error) {
	sig := ed448.Sign(k.key, data, eddsa.EdDSAEd448ContextString)

	return &EdDSAEd448Signature{
		Sig: sig,
	}, nil
}
