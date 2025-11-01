package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"math/big"
)

var defaultCurve = elliptic.P256()

type ECDSASecp256r1PrivateKey struct {
	key *ecdsa.PrivateKey
}

var _ kangarookey.PrivateKey = (*ECDSASecp256r1PrivateKey)(nil)

func (k *ECDSASecp256r1PrivateKey) Bytes() []byte {
	prefix, err := kangarooregistry.GetPrefixFromType(k.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration private-key<%s> panic: %v", k.Type(), err))
	}

	b := make([]byte, kangarooecdsa.ECDSAPrivateKeyBytesLength)
	k.key.D.FillBytes(b)
	return append([]byte{prefix}, b...)
}

func (k *ECDSASecp256r1PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *ECDSASecp256r1PrivateKey) IsValid() bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.D.Sign() > 0 && k.key.D.Cmp(defaultCurve.Params().N) < 0
}

func (k *ECDSASecp256r1PrivateKey) Type() string {
	return kangarooecdsa.ECDSASecp256r1Type
}

func (k *ECDSASecp256r1PrivateKey) PublicKey() kangarookey.PublicKey {
	pk := k.key.PublicKey
	return &ECDSASecp256r1PublicKey{
		Key: elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y),
	}
}

func (k *ECDSASecp256r1PrivateKey) Sign(data []byte) (kangarookey.Signature, error) {
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

	return &ECDSASecp256r1Signature{
		R: r,
		S: s,
	}, nil
}

func GenerateECDSASecp256r1PrivateKey() (kangarookey.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(defaultCurve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSASecp256r1PrivateKey{
		key: k,
	}, nil
}

func ECDSASecp256r1PrivateKeyFromBytes(b []byte) (kangarookey.PrivateKey, error) {
	if len(b) != kangarooecdsa.ECDSAPrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256r1Type, kangarooecdsa.ECDSAPrivateKeyBytesLength, len(b))
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

	return &ECDSASecp256r1PrivateKey{
		key: privKey,
	}, nil
}
