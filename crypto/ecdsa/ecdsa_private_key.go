package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto"
	"math/big"
	"strings"
)

const (
	ECDSAP256Type       = "ecdsa-P256"
	PrivateKeyLength    = 32
	PrivateKeyHexLength = PrivateKeyLength * 2
)

var defaultCurve = elliptic.P256()

type ECDSAPrivateKey struct {
	key *ecdsa.PrivateKey
}

var _ crypto.PrivateKey = (*ECDSAPrivateKey)(nil)

func (k *ECDSAPrivateKey) Bytes() []byte {
	b := make([]byte, PrivateKeyLength)
	k.key.D.FillBytes(b)
	return b
}

func (k *ECDSAPrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSAPrivateKey) IsValid() bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.D.Sign() > 0 && k.key.D.Cmp(defaultCurve.Params().N) < 0
}

func (k *ECDSAPrivateKey) Type() string {
	return ECDSAP256Type
}

func (k *ECDSAPrivateKey) PublicKey() crypto.PublicKey {
	pk := k.key.PublicKey
	return &ECDSAPublicKey{
		Key: elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y),
	}
}

func (k *ECDSAPrivateKey) Sign(data []byte) (crypto.Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.key, data)
	if err != nil {
		return nil, err
	}

	curveOrder := defaultCurve.Params().N
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2))

	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	return &ECDSASignature{
		R: r,
		S: s,
	}, nil
}

func GenerateECDSAPrivateKey() (crypto.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(defaultCurve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSAPrivateKey{
		key: k,
	}, nil
}

func ECDSAPrivateKeyFromBytes(b []byte) (crypto.PrivateKey, error) {
	if len(b) != PrivateKeyLength {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", PrivateKeyLength, len(b))
	}

	d := new(big.Int).SetBytes(b)
	if d.Sign() == 0 {
		return nil, fmt.Errorf("invalid private key: zero value")
	}
	if d.Cmp(defaultCurve.Params().N) >= 0 {
		return nil, fmt.Errorf("private key is larger than the curve order")
	}

	x, y := defaultCurve.ScalarBaseMult(b)
	pubKey := ecdsa.PublicKey{
		Curve: defaultCurve,
		X:     x,
		Y:     y,
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         d,
	}

	return &ECDSAPrivateKey{
		key: privKey,
	}, nil
}

func ECDSAPrivateKeyFromString(s string) (crypto.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")

	if len(s) != PrivateKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for private-key<%s> (%d), must be %d", ECDSAP256Type, len(s), PrivateKeyHexLength)
	}

	privKeybytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSAPrivateKeyFromBytes(privKeybytes)
}
