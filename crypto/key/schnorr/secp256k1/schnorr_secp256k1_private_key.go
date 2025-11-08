package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooschnorr "github.com/andantan/kangaroo/crypto/key/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrschnorr "github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

type SchnorrSecp256k1PrivateKey struct {
	key *secp256k1.PrivateKey
}

var _ key.PrivateKey = (*SchnorrSecp256k1PrivateKey)(nil)

func GenerateSchnorrSecp256k1PrivateKey() (key.PrivateKey, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &SchnorrSecp256k1PrivateKey{
		key: k,
	}, nil
}

func SchnorrSecp256k1PrivateKeyFromBytes(b []byte) (key.PrivateKey, error) {
	if len(b) != kangarooschnorr.SchnorrSecp256k1PrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d",
			kangarooschnorr.SchnorrSecp256k1Type, kangarooschnorr.SchnorrSecp256k1PrivateKeyBytesLength, len(b))
	}

	pk := secp256k1.PrivKeyFromBytes(b)

	return &SchnorrSecp256k1PrivateKey{
		key: pk,
	}, nil
}

func (k *SchnorrSecp256k1PrivateKey) Bytes() []byte {
	return k.key.Serialize()
}

func (k *SchnorrSecp256k1PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *SchnorrSecp256k1PrivateKey) ShortString(length int) string {
	ks := hex.EncodeToString(k.Bytes())
	if length > len(ks) {
		length = len(ks)
	}
	return "0x" + ks[:length]
}

func (k *SchnorrSecp256k1PrivateKey) IsValid() bool {
	if k == nil || k.key == nil {
		return false
	}

	return !k.key.Key.IsZero()
}

func (k *SchnorrSecp256k1PrivateKey) Type() string {
	return kangarooschnorr.SchnorrSecp256k1Type
}

func (k *SchnorrSecp256k1PrivateKey) PublicKey() key.PublicKey {
	pk := k.key.PubKey()
	return &SchnorrSecp256k1PublicKey{
		Key: pk.SerializeCompressed(),
	}
}

func (k *SchnorrSecp256k1PrivateKey) Sign(data []byte) (key.Signature, error) {
	sig, err := dcrschnorr.Sign(k.key, data)
	if err != nil {
		return nil, err
	}
	r := sig.R()
	s := sig.S()

	return &SchnorrSecp256k1Signature{
		R: &r,
		S: &s,
	}, nil
}
