package sr25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
)

type SchnorrSr25519Signature struct {
	s *schnorrkel.Signature
}

var _ key.Signature = (*SchnorrSr25519Signature)(nil)

func SchnorrSr25519SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != schnorr.SchnorrSr25519SignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d",
			schnorr.SchnorrSr25519Type, schnorr.SchnorrSr25519SignatureBytesLength, len(b))
	}

	a := [schnorr.SchnorrSr25519SignatureBytesLength]byte{}
	copy(a[:], b)
	s := &schnorrkel.Signature{}
	if err := s.Decode(a); err != nil {
		return nil, err
	}

	return &SchnorrSr25519Signature{
		s: s,
	}, nil
}

func (s *SchnorrSr25519Signature) Bytes() []byte {
	se := s.s.Encode()
	return append([]byte(nil), se[:]...)
}

func (s *SchnorrSr25519Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *SchnorrSr25519Signature) IsValid() bool {
	return s != nil && s.s != nil
}

func (s *SchnorrSr25519Signature) Type() string {
	return schnorr.SchnorrSr25519Type
}

func (s *SchnorrSr25519Signature) Equal(other key.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*SchnorrSr25519Signature)
	if !ok {
		return false
	}

	return bytes.Equal(s.Bytes(), otherSig.Bytes())
}

func (s *SchnorrSr25519Signature) Verify(pubKey key.PublicKey, data []byte) bool {
	schnorrPubKey, ok := pubKey.(*SchnorrSr25519PublicKey)
	if !ok {
		return false
	}

	a := [schnorr.SchnorrSr25519PublicKeyBytesLength]byte{}
	copy(a[:], schnorrPubKey.Key)
	dk := schnorrkel.PublicKey{}
	if err := dk.Decode(a); err != nil {
		return false
	}

	st := schnorrkel.NewSigningContext([]byte(schnorr.SchnorrSr25519ContextString), data)
	v, err := dk.Verify(s.s, st)
	if err != nil {
		return false
	}

	return v
}
