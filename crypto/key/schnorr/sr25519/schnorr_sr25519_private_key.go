package sr25519

import (
	"encoding/hex"
	"fmt"
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
)

type SchnorrSr25519PrivateKey struct {
	key *schnorrkel.SecretKey
}

var _ key.PrivateKey = (*SchnorrSr25519PrivateKey)(nil)

func GenerateSchnorrSr25519PrivateKey() (key.PrivateKey, error) {
	k, _, err := schnorrkel.GenerateKeypair()
	if err != nil {
		return nil, err
	}

	return &SchnorrSr25519PrivateKey{
		key: k,
	}, nil
}

func SchnorrSr25519PrivateKeyFromBytes(b []byte) (key.PrivateKey, error) {
	if len(b) != schnorr.SchnorrSr25519PrivateKeyBytesLength {
		return nil, fmt.Errorf("invalid bytes length for private-key<%s>: expected %d, got %d",
			schnorr.SchnorrSecp256k1Type, schnorr.SchnorrSr25519PrivateKeyBytesLength, len(b))
	}

	a := [schnorr.SchnorrSr25519PrivateKeyBytesLength]byte{}
	copy(a[:], b)
	k := &schnorrkel.SecretKey{}
	if err := k.Decode(a); err != nil {
		return nil, err
	}

	return &SchnorrSr25519PrivateKey{
		key: k,
	}, nil
}

func (k *SchnorrSr25519PrivateKey) Bytes() []byte {
	ke := k.key.Encode()
	return append([]byte(nil), ke[:]...)
}

func (k *SchnorrSr25519PrivateKey) String() string {
	return "0x" + hex.EncodeToString(k.Bytes())
}

func (k *SchnorrSr25519PrivateKey) ShortString(length int) string {
	ks := hex.EncodeToString(k.Bytes())
	if length > len(ks) {
		length = len(ks)
	}
	return "0x" + ks[:length]
}

func (k *SchnorrSr25519PrivateKey) IsValid() bool {
	return k != nil && k.key != nil
}

func (k *SchnorrSr25519PrivateKey) Type() string {
	return schnorr.SchnorrSr25519Type
}

func (k *SchnorrSr25519PrivateKey) PublicKey() key.PublicKey {
	pk, _ := k.key.Public()
	pkb := pk.Encode()

	return &SchnorrSr25519PublicKey{
		Key: pkb[:],
	}
}

func (k *SchnorrSr25519PrivateKey) Sign(data []byte) (key.Signature, error) {
	st := schnorrkel.NewSigningContext([]byte(schnorr.SchnorrSr25519ContextString), data)
	sig, err := k.key.Sign(st)
	if err != nil {
		return nil, err
	}

	return &SchnorrSr25519Signature{
		s: sig,
	}, nil
}
