package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

type EdDSAEd25519Signature struct {
	Point  [32]byte // R
	Scalar [32]byte // S
}

var _ kangarookey.Signature = (*EdDSAEd25519Signature)(nil)

func (s *EdDSAEd25519Signature) Bytes() []byte {
	prefix, err := kangarooregistry.GetKeyPrefixFromType(s.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration signature<%s> panic: %v", s.Type(), err))
	}
	b := append([]byte{prefix}, s.Point[:]...)
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
