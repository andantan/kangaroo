package ecdsa

import (
	"github.com/andantan/kangaroo/types"
	"github.com/andantan/kangaroo/types/sha256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestECDSAPrivateKey_SHA256_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateECDSAPrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, ECDSAP256Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	reloadedPrivKey, err := ECDSAPrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKey)

	// 3. String Round Trip
	privKeyString := privKey.String()
	reloadedPrivKeyFromString, err := ECDSAPrivateKeyFromString(privKeyString)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKeyFromString)
}

func TestECDSAPublicKey_SHA256_Lifecycle(t *testing.T) {
	privKey, err := GenerateECDSAPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 1. Validation and Type Check
	assert.True(t, pubKey.IsValid())
	assert.Equal(t, ECDSAP256Type, pubKey.Type())

	// 2. Bytes Round Trip
	pubKeyBytes := pubKey.Bytes()
	reloadedPubKey, err := ECDSAPublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKey))

	// 3. String Round Trip
	pubKeyString := pubKey.String()
	reloadedPubKeyFromString, err := ECDSAPublicKeyFromString(pubKeyString)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

	// 4. Address Derivation using the Derive
	addressDeriver := sha256.NewSHA256AddressDeriver()
	address := pubKey.Address(addressDeriver)
	assert.NotNil(t, address)
	assert.Equal(t, types.AddressLength, len(address.Bytes()))
}

func TestECDSASignature_SHA256_Lifecycle(t *testing.T) {
	privKey, _ := GenerateECDSAPrivateKey()
	hashDeriver := sha256.NewSHA256HashDeriver()
	dataHash := hashDeriver.Derive([]byte("test data"))

	signature, err := privKey.Sign(dataHash.Bytes())
	require.NoError(t, err)

	// 1. Validation (Low-S Rule) and Type Check
	assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
	assert.Equal(t, ECDSAP256Type, signature.Type())

	// 2. Bytes Round Trip
	sigBytes := signature.Bytes()
	reloadedSig, err := ECDSASignatureFromBytes(sigBytes)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSig))

	// 3. String Round Trip
	sigString := signature.String()
	reloadedSigFromString, err := ECDSASignatureFromString(sigString)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSigFromString))
}

func TestECDSASignature_SHA256_Verify(t *testing.T) {
	// --- Setup ---
	privKey, err := GenerateECDSAPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()
	hashDeriver := sha256.NewSHA256HashDeriver()
	dataHash := hashDeriver.Derive([]byte("correct data"))
	signature, err := privKey.Sign(dataHash.Bytes())
	require.NoError(t, err)

	// --- Test Cases ---
	t.Run("Verification with correct key and data should succeed", func(t *testing.T) {
		assert.True(t, signature.Verify(pubKey, dataHash.Bytes()))
	})

	t.Run("Verification with wrong data should fail", func(t *testing.T) {
		wrongDataHash := hashDeriver.Derive([]byte("wrong data"))
		assert.False(t, signature.Verify(pubKey, wrongDataHash.Bytes()))
	})

	t.Run("Verification with wrong key should fail", func(t *testing.T) {
		otherPrivKey, err := GenerateECDSAPrivateKey()
		assert.NoError(t, err)
		otherPubKey := otherPrivKey.PublicKey()
		assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
	})

	t.Run("Verification with invalid public key should fail", func(t *testing.T) {
		invalidPubKeyBytes := make([]byte, PublicKeyLength)
		invalidPubKey, err := ECDSAPublicKeyFromBytes(invalidPubKeyBytes)
		assert.NoError(t, err)
		assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
	})
}
