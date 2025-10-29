package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	"math/big"
	"strings"
)

const (
	SignatureLength    = 64
	SignatureHexLength = SignatureLength * 2
)

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

var _ crypto.Signature = (*ECDSASignature)(nil)

func (s *ECDSASignature) Bytes() []byte {
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	s.R.FillBytes(rBytes)
	s.S.FillBytes(sBytes)
	return append(rBytes, sBytes...)
}

func (s *ECDSASignature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *ECDSASignature) IsValid() bool {
	if s == nil || s.R == nil || s.S == nil {
		return false
	}
	curveOrder := defaultCurve.Params().N
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2))

	return s.S.Cmp(halfOrder) <= 0 && s.S.Sign() > 0 && s.R.Sign() > 0
}

func (s *ECDSASignature) Type() string {
	return ECDSAP256Type
}

func (s *ECDSASignature) Equal(other crypto.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*ECDSASignature)
	if !ok {
		return false
	}

	return s.R.Cmp(otherSig.R) == 0 && s.S.Cmp(otherSig.S) == 0
}

func (s *ECDSASignature) Verify(pubKey crypto.PublicKey, data []byte) bool {
	ecdsaPubKey, ok := pubKey.(*ECDSAPublicKey)
	if !ok {
		return false
	}

	x, y := elliptic.UnmarshalCompressed(defaultCurve, ecdsaPubKey.Key)
	if x == nil {
		return false
	}

	key := &ecdsa.PublicKey{
		Curve: defaultCurve,
		X:     x,
		Y:     y,
	}

	return ecdsa.Verify(key, data, s.R, s.S)
}

func ECDSASignatureFromBytes(b []byte) (crypto.Signature, error) {
	if len(b) != SignatureLength {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", SignatureLength, len(b))
	}
	r := new(big.Int).SetBytes(b[:32])
	s := new(big.Int).SetBytes(b[32:])
	return &ECDSASignature{
		R: r,
		S: s,
	}, nil
}

func ECDSASignatureFromString(s string) (crypto.Signature, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != SignatureHexLength {
		return nil, fmt.Errorf("invalid hex string length signature<%s> (%d), must be %d", ECDSAP256Type, len(s), SignatureHexLength)
	}

	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSASignatureFromBytes(sigBytes)
}
