package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
)

type EdDSAEd25519Signature struct {
	Sig []byte
}

var _ key.Signature = (*EdDSAEd25519Signature)(nil)

func EdDSAEd25519SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != eddsa.EdDSAEd25519SignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", eddsa.EdDSAEd25519Type, eddsa.EdDSAEd25519SignatureBytesLength, len(b))
	}

	sigBytes := append([]byte(nil), b...)
	return &EdDSAEd25519Signature{
		Sig: sigBytes,
	}, nil
}

func (s *EdDSAEd25519Signature) Bytes() []byte {
	return append([]byte(nil), s.Sig...)
}

func (s *EdDSAEd25519Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *EdDSAEd25519Signature) ShortString(length int) string {
	ss := hex.EncodeToString(s.Bytes())
	if length > len(ss) {
		length = len(ss)
	}
	return "0x" + ss[:length]
}

func (s *EdDSAEd25519Signature) IsValid() bool {
	if s.Sig == nil || len(s.Sig) != eddsa.EdDSAEd25519SignatureBytesLength {
		return false
	}

	return true
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

	return bytes.Equal(s.Sig, otherSig.Sig)
}

func (s *EdDSAEd25519Signature) Verify(pubkey key.PublicKey, data []byte) bool {
	pubKey, ok := pubkey.(*EdDSAEd25519PublicKey)
	if !ok {
		return false
	}

	return ed25519.Verify(pubKey.Key, data, s.Sig)
}
