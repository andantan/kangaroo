package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
	"strings"
)

type EdDSAEd25519Signature struct {
	Point  [32]byte // R
	Scalar [32]byte // S
}

var _ kangarookey.Signature = (*EdDSAEd25519Signature)(nil)

func (s *EdDSAEd25519Signature) Bytes() []byte {
	return append(s.Point[:], s.Scalar[:]...)
}

func (s *EdDSAEd25519Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *EdDSAEd25519Signature) IsValid() bool {
	return len(s.Bytes()) == kangarooeddsa.EdDSASignatureBytesLength
}

func (s *EdDSAEd25519Signature) Type() string {
	return kangarooeddsa.EdDSAEd25519Type
}

func (s *EdDSAEd25519Signature) Equal(other kangarookey.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*EdDSAEd25519Signature)
	if !ok {
		return false
	}

	return s.Point == otherSig.Point && s.Scalar == otherSig.Scalar
}

func (s *EdDSAEd25519Signature) Verify(pubkey kangarookey.PublicKey, data []byte) bool {
	eddsaPubKey, ok := pubkey.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	sig := append(s.Point[:], s.Scalar[:]...)
	return ed25519.Verify(eddsaPubKey.Key, data, sig)
}

func EdDSAEd25519SignatureFromBytes(b []byte) (kangarookey.Signature, error) {
	if len(b) != kangarooeddsa.EdDSASignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", kangarooeddsa.EdDSAEd25519Type, kangarooeddsa.EdDSASignatureBytesLength, len(b))
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

func EdDSAEd25519SignatureFromString(s string) (kangarookey.Signature, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangarooeddsa.EdDSASignatureHexLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", kangarooeddsa.EdDSAEd25519Type, kangarooeddsa.EdDSASignatureHexLength, len(s))
	}

	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return EdDSAEd25519SignatureFromBytes(sigBytes)
}
