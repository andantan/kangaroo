package crypto

import (
	"testing"

	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookeccak256 "github.com/andantan/kangaroo/crypto/hash/keccak256"
	kangaroosha256 "github.com/andantan/kangaroo/crypto/hash/sha256"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	kangaroosecp256k1 "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	kangaroosecp256r1 "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256r1"
	kangarooed25519 "github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHashable struct {
	data []byte
}

func (m *mockHashable) Hash(deriver kangaroohash.HashDeriver) (kangaroohash.Hash, error) {
	return deriver.Derive(m.data), nil
}

var _ kangaroohash.Hashable = (*mockHashable)(nil)

func TestSignAndVerify_Integration(t *testing.T) {
	testCases := []struct {
		name        string
		keySuite    kangarookey.KeySuite
		hashDeriver kangaroohash.HashDeriver
	}{
		{"ecdsa-secp256r1 with sha256", &kangaroosecp256r1.ECDSASecp256r1Suite{}, &kangaroosha256.Sha256HashDeriver{}},
		{"ecdsa-secp256k1 with sha256", &kangaroosecp256k1.ECDSASecp256k1Suite{}, &kangaroosha256.Sha256HashDeriver{}},
		{"eddsa-ed25519 with2 sha256", &kangarooed25519.EdDSAEd25519Suite{}, &kangaroosha256.Sha256HashDeriver{}},
		{"ecdsa-secp256r1 with keccak256", &kangaroosecp256r1.ECDSASecp256r1Suite{}, &kangarookeccak256.Keccak256HashDeriver{}},
		{"ecdsa-secp256k1 with keccak256", &kangaroosecp256k1.ECDSASecp256k1Suite{}, &kangarookeccak256.Keccak256HashDeriver{}},
		{"eddsa-ed25519 with2 keccak256", &kangarooed25519.EdDSAEd25519Suite{}, &kangarookeccak256.Keccak256HashDeriver{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Setup ---
			signer, err := tc.keySuite.GeneratePrivateKey()
			require.NoError(t, err, "key generation should succeed")
			pubKey := signer.PublicKey()

			itemToSign := &mockHashable{data: []byte("this is the data to be signed")}
			dataHash, err := itemToSign.Hash(tc.hashDeriver)
			require.NoError(t, err)

			// --- Action: Sign ---
			signature, err := Sign(signer, itemToSign, tc.hashDeriver)
			require.NoError(t, err, "signing should succeed")

			// --- Verification Scenarios ---
			t.Run("should succeed with correct data and key", func(t *testing.T) {
				err := VerifySignature(pubKey, signature, dataHash)
				assert.NoError(t, err, "verification with correct inputs should succeed")
			})

			t.Run("should fail with wrong data", func(t *testing.T) {
				wrongItem := &mockHashable{data: []byte("this is wrong data")}
				wrongDataHash, _ := wrongItem.Hash(tc.hashDeriver)

				err := VerifySignature(pubKey, signature, wrongDataHash)
				assert.Error(t, err, "verification with wrong data should fail")
			})

			t.Run("should fail with wrong public key", func(t *testing.T) {
				otherSigner, _ := tc.keySuite.GeneratePrivateKey()
				otherPubKey := otherSigner.PublicKey()

				err := VerifySignature(otherPubKey, signature, dataHash)
				assert.Error(t, err, "verification with wrong key should fail")
			})
		})
	}
}

func TestVerifySignature_MismatchedTypes(t *testing.T) {
	secp256r1Suite := &kangaroosecp256r1.ECDSASecp256r1Suite{}
	secp256r1Signer, _ := secp256r1Suite.GeneratePrivateKey()
	secp256r1Sig, _ := secp256r1Signer.Sign([]byte("data"))

	ed25519Suite := &kangarooed25519.EdDSAEd25519Suite{}
	ed25519Signer, _ := ed25519Suite.GeneratePrivateKey()
	ed25519PubKey := ed25519Signer.PublicKey()

	mockHash := &mockHashable{data: []byte("data")}
	sha256Deriver := &kangaroosha256.Sha256HashDeriver{}
	dataHash, _ := mockHash.Hash(sha256Deriver)

	err := VerifySignature(ed25519PubKey, secp256r1Sig, dataHash)
	assert.Error(t, err, "verification should fail with mismatched key and signature types")
	assert.Contains(t, err.Error(), "key type (eddsa-ed25519) does not match signature type (ecdsa-secp256r1)")
}
