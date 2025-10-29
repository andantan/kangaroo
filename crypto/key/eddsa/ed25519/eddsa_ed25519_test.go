package ed25519

import (
	"github.com/andantan/kangaroo/crypto/hash"
	keccak257 "github.com/andantan/kangaroo/crypto/hash/keccak256"
	"github.com/andantan/kangaroo/crypto/hash/ripemd160"
	sha257 "github.com/andantan/kangaroo/crypto/hash/sha256"
	eddsaformat "github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_EdDSA_Ed25519_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, eddsaformat.EdDSAEd25519Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	reloadedPrivKey, err := EdDSAEd25519PrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKey)

	// 3. String Round Trip
	privKeyString := privKey.String()
	reloadedPrivKeyFromString, err := EdDSAEd25519PrivateKeyFromString(privKeyString)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKeyFromString)
}

func Test_EdDSA_Ed25519_PublicKey_SHA256_Lifecycle(t *testing.T) {
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 1. Validation and Type Check
	assert.True(t, pubKey.IsValid())
	assert.Equal(t, eddsaformat.EdDSAEd25519Type, pubKey.Type())

	// 2. Bytes Round Trip
	pubKeyBytes := pubKey.Bytes()
	reloadedPubKey, err := EdDSAEd25519PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKey))

	// 3. String Round Trip
	pubKeyString := pubKey.String()
	reloadedPubKeyFromString, err := EdDSAEd25519PublicKeyFromString(pubKeyString)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

	// 4. Address Derivation using the Derive
	addressDeriver := sha257.NewSha256AddressDeriver()
	address := pubKey.Address(addressDeriver)
	assert.NotNil(t, address)
	assert.Equal(t, hash.AddressLength, len(address.Bytes()))
}

func Test_EdDSA_Ed25519_PublicKey_KECCAK256_Lifecycle(t *testing.T) {
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 1. Validation and Type Check
	assert.True(t, pubKey.IsValid())
	assert.Equal(t, eddsaformat.EdDSAEd25519Type, pubKey.Type())

	// 2. Bytes Round Trip
	pubKeyBytes := pubKey.Bytes()
	reloadedPubKey, err := EdDSAEd25519PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKey))

	// 3. String Round Trip
	pubKeyString := pubKey.String()
	reloadedPubKeyFromString, err := EdDSAEd25519PublicKeyFromString(pubKeyString)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

	// 4. Address Derivation using the Derive
	addressDeriver := keccak257.NewKeccak256AddressDeriver()
	address := pubKey.Address(addressDeriver)
	assert.NotNil(t, address)
	assert.Equal(t, hash.AddressLength, len(address.Bytes()))
}

func Test_EdDSA_Ed25519_PublicKey_RIPEMD160_Lifecycle(t *testing.T) {
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 1. Validation and Type Check
	assert.True(t, pubKey.IsValid())
	assert.Equal(t, eddsaformat.EdDSAEd25519Type, pubKey.Type())

	// 2. Bytes Round Trip
	pubKeyBytes := pubKey.Bytes()
	reloadedPubKey, err := EdDSAEd25519PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKey))

	// 3. String Round Trip
	pubKeyString := pubKey.String()
	reloadedPubKeyFromString, err := EdDSAEd25519PublicKeyFromString(pubKeyString)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

	// 4. Address Derivation using the Derive
	addressDeriver := ripemd160.NewRipemd160AddressDeriver()
	address := pubKey.Address(addressDeriver)
	assert.NotNil(t, address)
	assert.Equal(t, hash.AddressLength, len(address.Bytes()))
}

func Test_EdDSA_Ed25519_Signature_SHA256_Lifecycle(t *testing.T) {
	privKey, _ := GenerateEdDSAEd25519PrivateKey()
	hashDeriver := sha257.NewSha256HashDeriver()
	dataHash := hashDeriver.Derive([]byte("test data"))

	signature, err := privKey.Sign(dataHash.Bytes())
	require.NoError(t, err)

	// 1. Validation (Low-S Rule) and Type Check
	assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
	assert.Equal(t, eddsaformat.EdDSAEd25519Type, signature.Type())

	// 2. Bytes Round Trip
	sigBytes := signature.Bytes()
	reloadedSig, err := EdDSAEd25519SignatureFromBytes(sigBytes)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSig))

	// 3. String Round Trip
	sigString := signature.String()
	reloadedSigFromString, err := EdDSAEd25519SignatureFromString(sigString)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSigFromString))
}

func Test_EdDSA_Ed25519_Signature_KECCAK256_Lifecycle(t *testing.T) {
	privKey, _ := GenerateEdDSAEd25519PrivateKey()
	hashDeriver := keccak257.NewKeccak256HashDeriver()
	dataHash := hashDeriver.Derive([]byte("test data"))

	signature, err := privKey.Sign(dataHash.Bytes())
	require.NoError(t, err)

	// 1. Validation (Low-S Rule) and Type Check
	assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
	assert.Equal(t, eddsaformat.EdDSAEd25519Type, signature.Type())

	// 2. Bytes Round Trip
	sigBytes := signature.Bytes()
	reloadedSig, err := EdDSAEd25519SignatureFromBytes(sigBytes)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSig))

	// 3. String Round Trip
	sigString := signature.String()
	reloadedSigFromString, err := EdDSAEd25519SignatureFromString(sigString)
	require.NoError(t, err)
	assert.True(t, signature.Equal(reloadedSigFromString))
}

func Test_EdDSA_Ed25519_Signature_SHA256_Verify(t *testing.T) {
	// --- Setup ---
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()
	hashDeriver := sha257.NewSha256HashDeriver()
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
		otherPrivKey, err := GenerateEdDSAEd25519PrivateKey()
		assert.NoError(t, err)
		otherPubKey := otherPrivKey.PublicKey()
		assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
	})

	t.Run("Verification with invalid public key should fail", func(t *testing.T) {
		invalidPubKeyBytes := make([]byte, eddsaformat.EdDSAPublicKeyBytesLength)
		invalidPubKey, err := EdDSAEd25519PublicKeyFromBytes(invalidPubKeyBytes)
		assert.NoError(t, err)
		assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
	})
}

func Test_EdDSA_Ed25519_Signature_KECCAK256_Verify(t *testing.T) {
	// --- Setup ---
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()
	hashDeriver := keccak257.NewKeccak256HashDeriver()
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
		otherPrivKey, err := GenerateEdDSAEd25519PrivateKey()
		assert.NoError(t, err)
		otherPubKey := otherPrivKey.PublicKey()
		assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
	})

	t.Run("Verification with invalid public key should fail", func(t *testing.T) {
		invalidPubKeyBytes := make([]byte, eddsaformat.EdDSAPublicKeyBytesLength)
		invalidPubKey, err := EdDSAEd25519PublicKeyFromBytes(invalidPubKeyBytes)
		assert.NoError(t, err)
		assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
	})
}
