package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
)

type EdDSAEd25519Signature struct {
	Point  [32]byte // R
	Scalar [32]byte // S
}

var _ key.Signature = (*EdDSAEd25519Signature)(nil)

func EdDSAEd25519SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != eddsa.EdDSAEd25519SignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", eddsa.EdDSAEd25519Type, eddsa.EdDSAEd25519SignatureBytesLength, len(b))
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

func (s *EdDSAEd25519Signature) Bytes() []byte {
	b := append([]byte(nil), s.Point[:]...)
	b = append(b, s.Scalar[:]...)
	return b
}

func (s *EdDSAEd25519Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *EdDSAEd25519Signature) IsValid() bool {
	return s.Point != [32]byte{} && s.Scalar != [32]byte{}
}

func (s *EdDSAEd25519Signature) Type() string {
	return eddsa.EdDSAEd25519Type
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
	pubKey, ok := pubkey.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	sig := append(s.Point[:], s.Scalar[:]...)
	return ed25519.Verify(pubKey.Key, data, sig)
}
