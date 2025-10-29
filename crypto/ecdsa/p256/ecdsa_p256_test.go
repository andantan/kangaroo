package p256

import (
	ecdsaformat "github.com/andantan/kangaroo/crypto/ecdsa"
	"github.com/andantan/kangaroo/types/hash"
	"github.com/andantan/kangaroo/types/hash/keccak256"
	"github.com/andantan/kangaroo/types/hash/sha256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_ECDSA_P256_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, ecdsaformat.ECDSAP256Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	reloadedPrivKey, err := ECDSAP256PrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKey)

	// 3. String Round Trip
	privKeyString := privKey.String()
	reloadedPrivKeyFromString, err := ECDSAP256PrivateKeyFromString(privKeyString)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKeyFromString)
}

func Test_ECDSA_P256_PublicKey_SHA256_Lifecycle(t *testing.T) {
	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 1. Validation and Type Check
	assert.True(t, pubKey.IsValid())
	assert.Equal(t, ecdsaformat.ECDSAP256Type, pubKey.Type())

	// 2. Bytes Round Trip
	pubKeyBytes := pubKey.Bytes()
	reloadedPubKey, err := ECDSAP256PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKey))

	// 3. String Round Trip
	pubKeyString := pubKey.String()
	reloadedPubKeyFromString, err := ECDSAP256PublicKeyFromString(pubKeyString)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

	// 4. Address Derivation using the Derive
	addressDeriver := sha256.NewSha256AddressDeriver()
	address := pubKey.Address(addressDeriver)
	assert.NotNil(t, address)
	assert.Equal(t, hash.AddressLength, len(address.Bytes()))
}

func Test_ECDSA_P256_PublicKey_KECCAK256_Lifecycle(t *testing.T) {
	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 1. Validation and Type Check
	assert.True(t, pubKey.IsValid())
	assert.Equal(t, ecdsaformat.ECDSAP256Type, pubKey.Type())

	// 2. Bytes Round Trip
	pubKeyBytes := pubKey.Bytes()
	reloadedPubKey, err := ECDSAP256PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKey))

	// 3. String Round Trip
	pubKeyString := pubKey.String()
	reloadedPubKeyFromString, err := ECDSAP256PublicKeyFromString(pubKeyString)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

	// 4. Address Derivation using the Derive
	addressDeriver := keccak256.NewKeccak256AddressDeriver()
	address := pubKey.Address(addressDeriver)
	assert.NotNil(t, address)
	assert.Equal(t, hash.AddressLength, len(address.Bytes()))
}

func Test_ECDSA_P256_Signature_SHA256_Lifecycle(t *testing.T) {
	privKey, _ := GenerateECDSAP256PrivateKey()
	hashDeriver := sha256.NewSha256HashDeriver()
	dataHash := hashDeriver.Derive([]byte("test data"))

	signature, err := privKey.Sign(dataHash.Bytes())
	require.NoError(t, err)

	// 1. Validation (Low-S Rule) and Type Check
	assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
	assert.Equal(t, ecdsaformat.ECDSAP256Type, signature.Type())

	// 2. Bytes Round Trip
	sigBytes := signature.Bytes()
	reloadedSig, err := ECDSAP256SignatureFromBytes(sigBytes)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSig))

	// 3. String Round Trip
	sigString := signature.String()
	reloadedSigFromString, err := ECDSAP256SignatureFromString(sigString)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSigFromString))
}

func Test_ECDSA_P256_Signature_KECCAK256_Lifecycle(t *testing.T) {
	privKey, _ := GenerateECDSAP256PrivateKey()
	hashDeriver := keccak256.NewKeccak256HashDeriver()
	dataHash := hashDeriver.Derive([]byte("test data"))

	signature, err := privKey.Sign(dataHash.Bytes())
	require.NoError(t, err)

	// 1. Validation (Low-S Rule) and Type Check
	assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
	assert.Equal(t, ecdsaformat.ECDSAP256Type, signature.Type())

	// 2. Bytes Round Trip
	sigBytes := signature.Bytes()
	reloadedSig, err := ECDSAP256SignatureFromBytes(sigBytes)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSig))

	// 3. String Round Trip
	sigString := signature.String()
	reloadedSigFromString, err := ECDSAP256SignatureFromString(sigString)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSigFromString))
}

func Test_ECDSA_P256_Signature_SHA256_Verify(t *testing.T) {
	// --- Setup ---
	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()
	hashDeriver := sha256.NewSha256HashDeriver()
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
		otherPrivKey, err := GenerateECDSAP256PrivateKey()
		assert.NoError(t, err)
		otherPubKey := otherPrivKey.PublicKey()
		assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
	})

	t.Run("Verification with invalid public key should fail", func(t *testing.T) {
		invalidPubKeyBytes := make([]byte, ecdsaformat.ECDSAPublicKeyBytesLength)
		invalidPubKey, err := ECDSAP256PublicKeyFromBytes(invalidPubKeyBytes)
		assert.Error(t, err)
		assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
	})
}

func Test_ECDSA_P256_Signature_KECCAK256_Verify(t *testing.T) {
	// --- Setup ---
	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()
	hashDeriver := keccak256.NewKeccak256HashDeriver()
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
		otherPrivKey, err := GenerateECDSAP256PrivateKey()
		assert.NoError(t, err)
		otherPubKey := otherPrivKey.PublicKey()
		assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
	})

	t.Run("Verification with invalid public key should fail", func(t *testing.T) {
		invalidPubKeyBytes := make([]byte, ecdsaformat.ECDSAPublicKeyBytesLength)
		invalidPubKey, err := ECDSAP256PublicKeyFromBytes(invalidPubKeyBytes)
		assert.Error(t, err)
		assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
	})
}
