package secp256k1

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/hash/testutil"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_ECDSA_Secp256k1_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateECDSASecp256k1PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, ecdsa.ECDSASecp256k1Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	assert.Equal(t, ecdsa.ECDSAPrivateKeyBytesLength, len(privKeyBytes))
	reloadedPrivKey, err := ECDSASecp256k1PrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKey)
}

func Test_ECDSA_Secp256k1_PublicKey_Lifecycle(t *testing.T) {
	addressSuites := testutil.GetAddressSuiteTestCases()
	privKey, err := GenerateECDSASecp256k1PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	for _, tc := range addressSuites {
		t.Run(fmt.Sprintf("with %s address deriver", tc.Name), func(t *testing.T) {
			// 1. Validation and Type Check
			assert.True(t, pubKey.IsValid())
			assert.Equal(t, ecdsa.ECDSASecp256k1Type, pubKey.Type())

			// 2. Bytes Round Trip
			pubKeyBytes := pubKey.Bytes()
			assert.Equal(t, ecdsa.ECDSAPublicKeyBytesLength, len(pubKeyBytes))
			reloadedPubKey, err := ECDSASecp256k1PublicKeyFromBytes(pubKeyBytes)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(reloadedPubKey))

			// 3. Address Derivation using the current Deriver from the table
			address := pubKey.Address(tc.Suite.Deriver())
			assert.NotNil(t, address)
			assert.Equal(t, hash.AddressLength, len(address.Bytes()))
		})
	}
}

func Test_ECDSA_Secp256k1_Signature_Lifecycle(t *testing.T) {
	hashSuites := testutil.GetHashSuiteTestCases()
	privKey, err := GenerateECDSASecp256k1PrivateKey()
	require.NoError(t, err)

	for _, tc := range hashSuites {
		t.Run(fmt.Sprintf("with %s hash", tc.Name), func(t *testing.T) {
			dataHash := tc.Suite.Deriver().Derive([]byte("test data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			assert.True(t, signature.IsValid())
			assert.Equal(t, ecdsa.ECDSASecp256k1Type, signature.Type())

			sigBytes := signature.Bytes()
			assert.Equal(t, ecdsa.ECDSASignatureBytesLength, len(sigBytes))
			reloadedSig, err := ECDSASecp256k1SignatureFromBytes(sigBytes)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSig))
		})
	}
}

func Test_ECDSA_Secp256k1_Signature_Verify(t *testing.T) {
	hashSuites := testutil.GetHashSuiteTestCases()

	for _, tc := range hashSuites {
		t.Run(fmt.Sprintf("with %s hash", tc.Name), func(t *testing.T) {
			// --- Setup ---
			privKey, err := GenerateECDSASecp256k1PrivateKey()
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
				otherPrivKey, err := GenerateECDSASecp256k1PrivateKey()
				assert.NoError(t, err)
				otherPubKey := otherPrivKey.PublicKey()
				assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
			})

			t.Run("Verification with invalid public key should fail", func(t *testing.T) {
				invalidPubKeyBytes := make([]byte, ecdsa.ECDSAPublicKeyBytesLength)
				invalidPubKey, err := ECDSASecp256k1PublicKeyFromBytes(invalidPubKeyBytes)
				assert.Error(t, err)
				assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
			})
		})
	}
}
