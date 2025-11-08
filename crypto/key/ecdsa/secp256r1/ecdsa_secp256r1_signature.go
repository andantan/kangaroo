package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"math/big"
)

type ECDSASecp256r1Signature struct {
	R *big.Int
	S *big.Int
}

var _ key.Signature = (*ECDSASecp256r1Signature)(nil)

func (s *ECDSASecp256r1Signature) Bytes() []byte {
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	s.R.FillBytes(rBytes)
	s.S.FillBytes(sBytes)
	b := append([]byte(nil), rBytes...)
	b = append(b, sBytes...)
	return b
}

func (s *ECDSASecp256r1Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *ECDSASecp256r1Signature) ShortString(length int) string {
	ss := hex.EncodeToString(s.Bytes())
	if length > len(ss) {
		length = len(ss)
	}
	return "0x" + ss[:length]
}

func (s *ECDSASecp256r1Signature) IsValid() bool {
	if s == nil || s.R == nil || s.S == nil {
		return false
	}
	curveOrder := defaultCurve.Params().N
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2)) // low-s

	return s.S.Cmp(halfOrder) <= 0 && s.S.Sign() > 0 && s.R.Sign() > 0
}

func (s *ECDSASecp256r1Signature) Type() string {
	return kangarooecdsa.ECDSASecp256r1Type
}

func (s *ECDSASecp256r1Signature) Equal(other key.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*ECDSASecp256r1Signature)
	if !ok {
		return false
	}

	return s.R.Cmp(otherSig.R) == 0 && s.S.Cmp(otherSig.S) == 0
}

func (s *ECDSASecp256r1Signature) Verify(pubKey key.PublicKey, data []byte) bool {
	ecdsaPubKey, ok := pubKey.(*ECDSASecp256r1PublicKey)
	if !ok {
		return false
	}

	x, y := elliptic.UnmarshalCompressed(defaultCurve, ecdsaPubKey.Key)
	if x == nil {
		return false
	}

	k := &ecdsa.PublicKey{
		Curve: defaultCurve,
		X:     x,
		Y:     y,
	}

	return ecdsa.Verify(k, data, s.R, s.S)
}

func ECDSASecp256r1SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != kangarooecdsa.ECDSASecp256r1SignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256r1Type, kangarooecdsa.ECDSASecp256r1SignatureBytesLength, len(b))
	}
	r := new(big.Int).SetBytes(b[:32])
	s := new(big.Int).SetBytes(b[32:])
	return &ECDSASecp256r1Signature{
		R: r,
		S: s,
	}, nil
}
