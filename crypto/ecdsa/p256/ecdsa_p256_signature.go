package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	ecdsaformat "github.com/andantan/kangaroo/crypto/ecdsa"
	"math/big"
	"strings"
)

type ECDSAP256Signature struct {
	R *big.Int
	S *big.Int
}

var _ crypto.Signature = (*ECDSAP256Signature)(nil)

func (s *ECDSAP256Signature) Bytes() []byte {
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	s.R.FillBytes(rBytes)
	s.S.FillBytes(sBytes)
	return append(rBytes, sBytes...)
}

func (s *ECDSAP256Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *ECDSAP256Signature) IsValid() bool {
	if s == nil || s.R == nil || s.S == nil {
		return false
	}
	curveOrder := defaultCurve.Params().N
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2)) // low-s

	return s.S.Cmp(halfOrder) <= 0 && s.S.Sign() > 0 && s.R.Sign() > 0
}

func (s *ECDSAP256Signature) Type() string {
	return ecdsaformat.ECDSAP256Type
}

func (s *ECDSAP256Signature) Equal(other crypto.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*ECDSAP256Signature)
	if !ok {
		return false
	}

	return s.R.Cmp(otherSig.R) == 0 && s.S.Cmp(otherSig.S) == 0
}

func (s *ECDSAP256Signature) Verify(pubKey crypto.PublicKey, data []byte) bool {
	ecdsaPubKey, ok := pubKey.(*ECDSAP256PublicKey)
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

func ECDSAP256SignatureFromBytes(b []byte) (crypto.Signature, error) {
	if len(b) != ecdsaformat.ECDSASignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", ecdsaformat.ECDSAP256Type, ecdsaformat.ECDSASignatureBytesLength, len(b))
	}
	r := new(big.Int).SetBytes(b[:32])
	s := new(big.Int).SetBytes(b[32:])
	return &ECDSAP256Signature{
		R: r,
		S: s,
	}, nil
}

func ECDSAP256SignatureFromString(s string) (crypto.Signature, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != ecdsaformat.ECDSASignatureHexLength {
		return nil, fmt.Errorf("invalid hex string length for signature<%s>: expected %d, got %d", ecdsaformat.ECDSAP256Type, ecdsaformat.ECDSASignatureHexLength, len(s))
	}

	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSAP256SignatureFromBytes(sigBytes)
}
