package ed25519

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/hash/testutil"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_EdDSA_Ed25519_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, eddsa.EdDSAEd25519Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	assert.Equal(t, eddsa.EdDSAPrivateKeyBytesLength, len(privKeyBytes))
	reloadedPrivKey, err := EdDSAEd25519PrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKey)
}

func Test_EdDSA_Ed25519_PublicKey_Lifecycle(t *testing.T) {
	addressSuites := testutil.GetAddressSuiteTestCases()
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	for _, tc := range addressSuites {
		t.Run(fmt.Sprintf("with %s address deriver", tc.Name), func(t *testing.T) {
			// 1. Validation and Type Check
			assert.True(t, pubKey.IsValid())
			assert.Equal(t, eddsa.EdDSAEd25519Type, pubKey.Type())

			// 2. Bytes Round Trip
			pubKeyBytes := pubKey.Bytes()
			assert.Equal(t, eddsa.EdDSAPublicKeyBytesLength, len(pubKeyBytes))
			reloadedPubKey, err := EdDSAEd25519PublicKeyFromBytes(pubKeyBytes)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(reloadedPubKey))

			// 3. Address Derivation using the current Deriver from the table
			address := pubKey.Address(tc.Suite.Deriver())
			assert.NotNil(t, address)
			assert.Equal(t, hash.AddressLength, len(address.Bytes()))
		})
	}
}

func Test_EdDSA_Ed25519_Signature_Lifecycle(t *testing.T) {
	hashSuites := testutil.GetHashSuiteTestCases()
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)

	for _, tc := range hashSuites {
		t.Run(fmt.Sprintf("with %s hash", tc.Name), func(t *testing.T) {
			dataHash := tc.Suite.Deriver().Derive([]byte("test data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			assert.True(t, signature.IsValid())
			assert.Equal(t, eddsa.EdDSAEd25519Type, signature.Type())

			sigBytes := signature.Bytes()
			assert.Equal(t, eddsa.EdDSASignatureBytesLength, len(sigBytes))
			reloadedSig, err := EdDSAEd25519SignatureFromBytes(sigBytes)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSig))
		})
	}
}

func Test_EdDSA_Ed25519_Signature_Verify(t *testing.T) {
	hashSuites := testutil.GetHashSuiteTestCases()

	for _, tc := range hashSuites {
		t.Run(fmt.Sprintf("with %s hash", tc.Name), func(t *testing.T) {
			// --- Setup ---
			privKey, err := GenerateEdDSAEd25519PrivateKey()
			require.NoError(t, err)
			pubKey := privKey.PublicKey()

			correctData := []byte("correct data")
			wrongData := []byte("wrong data")

			signature, err := privKey.Sign(correctData)
			require.NoError(t, err)

			// --- Test Cases ---
			t.Run("Verification with correct key and data should succeed", func(t *testing.T) {
				assert.True(t, signature.Verify(pubKey, correctData))
			})

			t.Run("Verification with wrong data should fail", func(t *testing.T) {
				assert.False(t, signature.Verify(pubKey, wrongData))
			})

			t.Run("Verification with wrong key should fail", func(t *testing.T) {
				otherPrivKey, err := GenerateEdDSAEd25519PrivateKey()
				assert.NoError(t, err)
				otherPubKey := otherPrivKey.PublicKey()
				assert.False(t, signature.Verify(otherPubKey, correctData))
			})

			t.Run("Verification with invalid public key should fail", func(t *testing.T) {
				invalidPubKeyBytes := make([]byte, eddsa.EdDSAPublicKeyBytesLength)
				invalidPubKey, err := EdDSAEd25519PublicKeyFromBytes(invalidPubKeyBytes)
				assert.NoError(t, err)
				assert.False(t, signature.Verify(invalidPubKey, correctData))
			})
		})
	}
}
