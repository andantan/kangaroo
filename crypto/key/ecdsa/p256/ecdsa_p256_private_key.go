package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"math/big"
	"strings"
)

var defaultCurve = elliptic.P256()

type ECDSAP256PrivateKey struct {
	key *ecdsa.PrivateKey
}

var _ kangarookey.PrivateKey = (*ECDSAP256PrivateKey)(nil)

func (k *ECDSAP256PrivateKey) Bytes() []byte {
	b := make([]byte, kangarooecdsa.ECDSAPrivateKeyBytesLength)
	k.key.D.FillBytes(b)
	return b
}

func (k *ECDSAP256PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSAP256PrivateKey) IsValid() bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.D.Sign() > 0 && k.key.D.Cmp(defaultCurve.Params().N) < 0
}

func (k *ECDSAP256PrivateKey) Type() string {
	return kangarooecdsa.ECDSAP256Type
}

func (k *ECDSAP256PrivateKey) PublicKey() kangarookey.PublicKey {
	pk := k.key.PublicKey
	return &ECDSAP256PublicKey{
		Key: elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y),
	}
}

func (k *ECDSAP256PrivateKey) Sign(data []byte) (kangarookey.Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.key, data)
	if err != nil {
		return nil, err
	}

	curveOrder := defaultCurve.Params().N
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2))

	// low-s enforcement
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	return &ECDSAP256Signature{
		R: r,
		S: s,
	}, nil
}

func GenerateECDSAP256PrivateKey() (kangarookey.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(defaultCurve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSAP256PrivateKey{
		key: k,
	}, nil
}

func ECDSAP256PrivateKeyFromBytes(b []byte) (kangarookey.PrivateKey, error) {
	if len(b) != kangarooecdsa.ECDSAPrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", kangarooecdsa.ECDSAP256Type, kangarooecdsa.ECDSAPrivateKeyBytesLength, len(b))
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

	return &ECDSAP256PrivateKey{
		key: privKey,
	}, nil
}

func ECDSAP256PrivateKeyFromString(s string) (kangarookey.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangarooecdsa.ECDSAPrivateKeyHexLength {
		return nil, fmt.Errorf("invalid hex string length for private-key<%s>: expected %d, got %d", kangarooecdsa.ECDSAP256Type, len(s), kangarooecdsa.ECDSAPrivateKeyHexLength)
	}

	privKeyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSAP256PrivateKeyFromBytes(privKeyBytes)
}
