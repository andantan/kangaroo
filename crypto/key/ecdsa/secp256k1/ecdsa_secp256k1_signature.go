package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	ecdsaformat "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"strings"
)

type ECDSASecp256k1Signature struct {
	R *secp256k1.ModNScalar
	S *secp256k1.ModNScalar
}

var _ key.Signature = (*ECDSASecp256k1Signature)(nil)

func (s *ECDSASecp256k1Signature) Bytes() []byte {
	rArr := [32]byte{}
	sArr := [32]byte{}
	s.R.PutBytes(&rArr)
	s.S.PutBytes(&sArr)
	return append(rArr[:], sArr[:]...)
}

func (s *ECDSASecp256k1Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *ECDSASecp256k1Signature) IsValid() bool {
	return s != nil && s.R != nil && s.S != nil
}

func (s *ECDSASecp256k1Signature) Type() string {
	return ecdsaformat.ECDSASecp256k1Type
}

func (s *ECDSASecp256k1Signature) Equal(other key.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*ECDSASecp256k1Signature)
	if !ok {
		return false
	}

	return s.R.Equals(otherSig.R) && s.S.Equals(otherSig.S)
}

func (s *ECDSASecp256k1Signature) Verify(pubkey key.PublicKey, data []byte) bool {
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

func ECDSASecp256k1SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != ecdsaformat.ECDSASignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d", ecdsaformat.ECDSASecp256k1Type, ecdsaformat.ECDSASignatureBytesLength, len(b))
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

func ECDSASecp256k1SignatureFromString(s string) (key.Signature, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != ecdsaformat.ECDSASignatureHexLength {
		return nil, fmt.Errorf("invalid hex string length for signature<%s>: expected %d, got %d", ecdsaformat.ECDSASecp256k1Type, ecdsaformat.ECDSASignatureHexLength, len(s))
	}

	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ECDSASecp256k1SignatureFromBytes(sigBytes)
}
