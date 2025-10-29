package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	eddsaformat "github.com/andantan/kangaroo/crypto/key/eddsa"
	"strings"
)

type EdDSAEd25519Signature struct {
	Point  [32]byte // R
	Scalar [32]byte // S
}

var _ key.Signature = (*EdDSAEd25519Signature)(nil)

func (s *EdDSAEd25519Signature) Bytes() []byte {
	return append(s.Point[:], s.Scalar[:]...)
}

func (s *EdDSAEd25519Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *EdDSAEd25519Signature) IsValid() bool {
	return len(s.Bytes()) == eddsaformat.EdDSASignatureBytesLength
}

func (s *EdDSAEd25519Signature) Type() string {
	return eddsaformat.EdDSAEd25519Type
}

func (s *EdDSAEd25519Signature) Equal(other key.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*EdDSAEd25519Signature)
	if !ok {
		return false
	}

	return s.Point == otherSig.Point && s.Scalar == otherSig.Scalar
}

func (s *EdDSAEd25519Signature) Verify(pubkey key.PublicKey, data []byte) bool {
	eddsaPubKey, ok := pubkey.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	sig := append(s.Point[:], s.Scalar[:]...)
	return ed25519.Verify(eddsaPubKey.Key, data, sig)
}

func EdDSAEd25519SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != eddsaformat.EdDSASignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", eddsaformat.EdDSAEd25519Type, eddsaformat.EdDSASignatureBytesLength, len(b))
	}

	pointArr := [32]byte{}
	scalarArr := [32]byte{}
	copy(pointArr[:], b[:32])
	copy(scalarArr[:], b[32:])

	return &EdDSAEd25519Signature{
		Point:  pointArr,
		Scalar: scalarArr,
	}, nil
}

func EdDSAEd25519SignatureFromString(s string) (key.Signature, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != eddsaformat.EdDSASignatureHexLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", eddsaformat.EdDSAEd25519Type, eddsaformat.EdDSASignatureHexLength, len(s))
	}

	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return EdDSAEd25519SignatureFromBytes(sigBytes)
}
