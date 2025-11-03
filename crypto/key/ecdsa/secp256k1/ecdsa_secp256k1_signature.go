package secp256k1

import (
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"strings"
)

type ECDSASecp256k1Signature struct {
	R *secp256k1.ModNScalar
	S *secp256k1.ModNScalar
}

var _ kangarookey.Signature = (*ECDSASecp256k1Signature)(nil)

func (s *ECDSASecp256k1Signature) Bytes() []byte {
	prefix, err := kangarooregistry.GetKeyPrefixFromType(s.Type())
	if err != nil {
		panic(fmt.Sprintf("configuration signature<%s> panic: %v", s.Type(), err))
	}
	rArr := [32]byte{}
	sArr := [32]byte{}
	s.R.PutBytes(&rArr)
	s.S.PutBytes(&sArr)
	b := append([]byte{prefix}, rArr[:]...)
	b = append(b, sArr[:]...)
	return b
}

func (s *ECDSASecp256k1Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *ECDSASecp256k1Signature) IsValid() bool {
	if s == nil || s.R == nil || s.S == nil {
		return false
	}
	if s.S.IsOverHalfOrder() {
		return false
	}
	return true
}

func (s *ECDSASecp256k1Signature) Type() string {
	return kangarooecdsa.ECDSASecp256k1Type
}

func (s *ECDSASecp256k1Signature) Equal(other kangarookey.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*ECDSASecp256k1Signature)
	if !ok {
		return false
	}

	return s.R.Equals(otherSig.R) && s.S.Equals(otherSig.S)
}

func (s *ECDSASecp256k1Signature) Verify(pubkey kangarookey.PublicKey, data []byte) bool {
	ecdsaPubKey, ok := pubkey.(*ECDSASecp256k1PublicKey)
	if !ok {
		return false
	}

	pk, err := secp256k1.ParsePubKey(ecdsaPubKey.Key)
	if err != nil {
		return false
	}

	sig := ecdsa.NewSignature(s.R, s.S)

	return sig.Verify(data, pk)
}

func ECDSASecp256k1SignatureFromBytes(b []byte) (kangarookey.Signature, error) {
	if len(b) != kangarooecdsa.ECDSASignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256k1Type, kangarooecdsa.ECDSASignatureBytesLength, len(b))
	}

	rArr := [32]byte{}
	sArr := [32]byte{}
	copy(rArr[:], b[:32])
	copy(sArr[:], b[32:])

	r := new(secp256k1.ModNScalar)
	s := new(secp256k1.ModNScalar)
	r.SetBytes(&rArr)
	s.SetBytes(&sArr)

	return &ECDSASecp256k1Signature{
		R: r,
		S: s,
	}, nil
}

func ECDSASecp256k1SignatureFromString(s string) (kangarookey.Signature, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != kangarooecdsa.ECDSASignatureHexLength {
		return nil, fmt.Errorf("invalid hex string length for signature<%s>: expected %d, got %d", kangarooecdsa.ECDSASecp256k1Type, kangarooecdsa.ECDSASignatureHexLength, len(s))
	}

	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSASecp256k1SignatureFromBytes(sigBytes)
}
