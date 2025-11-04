package secp256r1

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/hash/keccak256"
	"github.com/andantan/kangaroo/crypto/hash/ripemd160"
	"github.com/andantan/kangaroo/crypto/hash/sha256"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_ECDSA_Secp256r1_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateECDSASecp256r1PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, ecdsa.ECDSASecp256r1Type, privKey.Type())

	// 2. Bytes Round Trip
	privKeyBytes := privKey.Bytes()
	assert.Equal(t, ecdsa.ECDSAPrivateKeyBytesLength, len(privKeyBytes))
	reloadedPrivKey, err := ECDSASecp256r1PrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	assert.Equal(t, privKey, reloadedPrivKey)
}

func Test_ECDSA_Secp256r1_PublicKey_Lifecycle(t *testing.T) {
	derivers := []struct {
		name    string
		deriver hash.AddressDeriver
	}{
		{"SHA256", &sha256.Sha256AddressDeriver{}},
		{"KECCAK256", &keccak256.Keccak256AddressDeriver{}},
		{"RIPEMD160", &ripemd160.Ripemd160AddressDeriver{}},
	}

	privKey, err := GenerateECDSASecp256r1PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	for _, tc := range derivers {
		t.Run(fmt.Sprintf("with %s address deriver", tc.name), func(t *testing.T) {
			// 1. Validation and Type Check
			assert.True(t, pubKey.IsValid())
			assert.Equal(t, ecdsa.ECDSASecp256r1Type, pubKey.Type())

			// 2. Bytes Round Trip
			pubKeyBytes := pubKey.Bytes()
			assert.Equal(t, ecdsa.ECDSAPublicKeyBytesLength, len(pubKeyBytes))
			reloadedPubKey, err := ECDSASecp256r1PublicKeyFromBytes(pubKeyBytes)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(reloadedPubKey))

			// 3. Address Derivation using the current Deriver from the table
			address := pubKey.Address(tc.deriver)
			assert.NotNil(t, address)
			assert.Equal(t, hash.AddressLength, len(address.Bytes()))
		})
	}
}

func Test_ECDSA_Secp256r1_Signature_Lifecycle(t *testing.T) {
	hashDerivers := []struct {
		name    string
		deriver hash.HashDeriver
	}{
		{"SHA256", &sha256.Sha256HashDeriver{}},
		{"KECCAK256", &keccak256.Keccak256HashDeriver{}},
	}

	privKey, err := GenerateECDSASecp256r1PrivateKey()
	require.NoError(t, err)

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
			dataHash := tc.deriver.Derive([]byte("test data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
			assert.Equal(t, ecdsa.ECDSASecp256r1Type, signature.Type())

			sigBytes := signature.Bytes()
			assert.Equal(t, ecdsa.ECDSASignatureBytesLength, len(sigBytes))
			reloadedSig, err := ECDSASecp256r1SignatureFromBytes(sigBytes)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSig))
		})
	}
}

func Test_ECDSA_Secp256r1_Signature_Verify(t *testing.T) {
	hashDerivers := []struct {
		name    string
		deriver hash.HashDeriver
	}{
		{"SHA256", &sha256.Sha256HashDeriver{}},
		{"KECCAK256", &keccak256.Keccak256HashDeriver{}},
	}

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
			// --- Setup ---
			privKey, err := GenerateECDSASecp256r1PrivateKey()
			require.NoError(t, err)
			pubKey := privKey.PublicKey()

			dataHash := tc.deriver.Derive([]byte("correct data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			// --- Test Cases ---
			t.Run("Verification with correct key and data should succeed", func(t *testing.T) {
				assert.True(t, signature.Verify(pubKey, dataHash.Bytes()))
			})

			t.Run("Verification with wrong data should fail", func(t *testing.T) {
				wrongDataHash := tc.deriver.Derive([]byte("wrong data"))
				assert.False(t, signature.Verify(pubKey, wrongDataHash.Bytes()))
			})

			t.Run("Verification with wrong key should fail", func(t *testing.T) {
				otherPrivKey, err := GenerateECDSASecp256r1PrivateKey()
				assert.NoError(t, err)
				otherPubKey := otherPrivKey.PublicKey()
				assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
			})

			t.Run("Verification with invalid public key should fail", func(t *testing.T) {
				invalidPubKeyBytes := make([]byte, ecdsa.ECDSAPublicKeyBytesLength)
				invalidPubKey, err := ECDSASecp256r1PublicKeyFromBytes(invalidPubKeyBytes)
				assert.Error(t, err)
				assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
			})
		})
	}
}
