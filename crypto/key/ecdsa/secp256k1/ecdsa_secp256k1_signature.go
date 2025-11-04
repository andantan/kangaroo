package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
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
	b := append([]byte(nil), rArr[:]...)
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

	sig := dcrecdsa.NewSignature(s.R, s.S)

	return sig.Verify(data, pk)
}

func ECDSASecp256k1SignatureFromBytes(b []byte) (key.Signature, error) {
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
