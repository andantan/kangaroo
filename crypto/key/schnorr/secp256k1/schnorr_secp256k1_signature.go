package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooschnorr "github.com/andantan/kangaroo/crypto/key/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrschnorr "github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

type SchnorrSecp256k1Signature struct {
	R *secp256k1.FieldVal
	S *secp256k1.ModNScalar
}

var _ key.Signature = (*SchnorrSecp256k1Signature)(nil)

func SchnorrSecp256k1SignatureFromBytes(b []byte) (key.Signature, error) {
	if len(b) != kangarooschnorr.SchnorrSecp256k1SignatureBytesLength {
		return nil, fmt.Errorf("invalid bytes length for signature<%s>: expected %d, got %d",
			kangarooschnorr.SchnorrSecp256k1Type, kangarooschnorr.SchnorrSecp256k1SignatureBytesLength, len(b))
	}

	rArr := [32]byte{}
	sArr := [32]byte{}
	copy(rArr[:], b[:32])
	copy(sArr[:], b[32:])

	r := new(secp256k1.FieldVal)
	s := new(secp256k1.ModNScalar)
	r.SetBytes(&rArr)
	s.SetBytes(&sArr)

	return &SchnorrSecp256k1Signature{
		R: r,
		S: s,
	}, nil
}

func (s *SchnorrSecp256k1Signature) Bytes() []byte {
	rArr := [32]byte{}
	sArr := [32]byte{}
	s.R.PutBytes(&rArr)
	s.S.PutBytes(&sArr)
	b := append([]byte(nil), rArr[:]...)
	b = append(b, sArr[:]...)
	return b
}

func (s *SchnorrSecp256k1Signature) String() string {
	return "0x" + hex.EncodeToString(s.Bytes())
}

func (s *SchnorrSecp256k1Signature) ShortString(length int) string {
	ss := hex.EncodeToString(s.Bytes())
	if length > len(ss) {
		length = len(ss)
	}
	return "0x" + ss[:length]
}

func (s *SchnorrSecp256k1Signature) IsValid() bool {
	return s != nil && s.R != nil && s.S != nil
}

func (s *SchnorrSecp256k1Signature) Type() string {
	return kangarooschnorr.SchnorrSecp256k1Type
}

func (s *SchnorrSecp256k1Signature) Equal(other key.Signature) bool {
	if s == nil || other == nil {
		return false
	}

	otherSig, ok := other.(*SchnorrSecp256k1Signature)
	if !ok {
		return false
	}

	return s.R.Equals(otherSig.R) && s.S.Equals(otherSig.S)
}

func (s *SchnorrSecp256k1Signature) Verify(pubKey key.PublicKey, data []byte) bool {
	schnorrPubKey, ok := pubKey.(*SchnorrSecp256k1PublicKey)
	if !ok {
		return false
	}

	pk, err := dcrschnorr.ParsePubKey(schnorrPubKey.Key)
	if err != nil {
		return false
	}

	sig := dcrschnorr.NewSignature(s.R, s.S)

	return sig.Verify(data, pk)
}
