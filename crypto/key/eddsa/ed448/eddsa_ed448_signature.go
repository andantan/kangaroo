package ed448

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/cloudflare/circl/sign/ed448"
)

type EdDSAEd448Signature struct {
	Sig []byte
}

var _ key.Signature = (*EdDSAEd448Signature)(nil)

func EdDSAEd448SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != eddsa.EdDSAEd448SignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", eddsa.EdDSAEd448Type, eddsa.EdDSAEd448SignatureBytesLength, len(b))
	}

	sigBytes := append([]byte(nil), b...)
	return &EdDSAEd448Signature{
		Sig: sigBytes,
	}, nil
}

func (s *EdDSAEd448Signature) Bytes() []byte {
	return append([]byte(nil), s.Sig...)
}

func (s *EdDSAEd448Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *EdDSAEd448Signature) ShortString(length int) string {
	ss := hex.EncodeToString(s.Bytes())
	if length > len(ss) {
		length = len(ss)
	}
	return "0x" + ss[:length]
}

func (s *EdDSAEd448Signature) Type() string {
	return eddsa.EdDSAEd448Type
}

func (s *EdDSAEd448Signature) IsValid() bool {
	if s.Sig == nil || len(s.Sig) != eddsa.EdDSAEd448SignatureBytesLength {
		return false
	}

	return true
}

func (s *EdDSAEd448Signature) Equal(other key.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*EdDSAEd448Signature)
	if !ok {
		return false
	}

	return bytes.Equal(s.Sig, otherSig.Sig)
}

func (s *EdDSAEd448Signature) Verify(pubkey key.PublicKey, data []byte) bool {
	pubKey, ok := pubkey.(*EdDSAEd448PublicKey)
	if !ok {
		return false
	}

	return ed448.Verify(pubKey.Key, data, s.Sig, eddsa.EdDSAEd448ContextString)
}
