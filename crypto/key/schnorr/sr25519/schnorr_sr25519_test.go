package sr25519

import (
	"bytes"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/hash/testutil"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_SCHNORR_Sr25519_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateSchnorrSr25519PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, schnorr.SchnorrSr25519Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	assert.Equal(t, schnorr.SchnorrSr25519PrivateKeyBytesLength, len(privKeyBytes))
	reloadedPrivKey, err := SchnorrSr25519PrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(privKey.Bytes(), reloadedPrivKey.Bytes()))
}

func Test_SCHNORR_Sr25519_PublicKey_Lifecycle(t *testing.T) {
	addressSuites := testutil.GetAddressSuiteTestCases(t)
	privKey, err := GenerateSchnorrSr25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	for _, tc := range addressSuites {
		t.Run(fmt.Sprintf("with %s address deriver", tc.Name), func(t *testing.T) {
			// 1. Validation and Type Check
			assert.True(t, pubKey.IsValid())
			assert.Equal(t, schnorr.SchnorrSr25519Type, pubKey.Type())

			// 2. Bytes Round Trip
			pubKeyBytes := pubKey.Bytes()
			assert.Equal(t, schnorr.SchnorrSr25519PublicKeyBytesLength, len(pubKeyBytes))
			reloadedPubKey, err := SchnorrSr25519PublicKeyFromBytes(pubKeyBytes)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(reloadedPubKey))

			// 3. Address Derivation using the current Deriver from the table
			address := pubKey.Address(tc.Suite.Deriver())
			assert.NotNil(t, address)
			assert.Equal(t, hash.AddressLength, len(address.Bytes()))
		})
	}
}

func Test_SCHNORR_Sr25519_Signature_Lifecycle(t *testing.T) {
	hashSuites := testutil.GetHashSuiteTestCases(t)
	privKey, err := GenerateSchnorrSr25519PrivateKey()
	require.NoError(t, err)

	for _, tc := range hashSuites {
		t.Run(fmt.Sprintf("with %s hash", tc.Name), func(t *testing.T) {
			dataHash := tc.Suite.Deriver().Derive([]byte("test data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			assert.True(t, signature.IsValid())
			assert.Equal(t, schnorr.SchnorrSr25519Type, signature.Type())

			sigBytes := signature.Bytes()
			assert.Equal(t, schnorr.SchnorrSr25519SignatureBytesLength, len(sigBytes))
			reloadedSig, err := SchnorrSr25519SignatureFromBytes(sigBytes)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSig))
		})
	}
}

func Test_SCHNORR_Sr25519_Signature_Verify(t *testing.T) {
	hashSuites := testutil.GetHashSuiteTestCases(t)

	for _, tc := range hashSuites {
		t.Run(fmt.Sprintf("with %s hash", tc.Name), func(t *testing.T) {
			// --- Setup ---
			privKey, err := GenerateSchnorrSr25519PrivateKey()
			require.NoError(t, err)
			pubKey := privKey.PublicKey()

			dataHash := tc.Suite.Deriver().Derive([]byte("correct data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			// --- Test Cases ---
			t.Run("Verification with correct key and data should succeed", func(t *testing.T) {
				assert.True(t, signature.Verify(pubKey, dataHash.Bytes()))
			})

			t.Run("Verification with wrong data should fail", func(t *testing.T) {
				wrongDataHash := tc.Suite.Deriver().Derive([]byte("wrong data"))
				assert.False(t, signature.Verify(pubKey, wrongDataHash.Bytes()))
			})

			t.Run("Verification with wrong key should fail", func(t *testing.T) {
				otherPrivKey, err := GenerateSchnorrSr25519PrivateKey()
				assert.NoError(t, err)
				otherPubKey := otherPrivKey.PublicKey()
				assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
			})

			t.Run("Verification with invalid public key should fail", func(t *testing.T) {
				invalidPubKeyBytes := make([]byte, schnorr.SchnorrSr25519PublicKeyBytesLength)
				invalidPubKey, err := SchnorrSr25519PublicKeyFromBytes(invalidPubKeyBytes)
				assert.Error(t, err)
				assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
			})
		})
	}
}
