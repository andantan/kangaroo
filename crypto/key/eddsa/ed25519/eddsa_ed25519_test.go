package ed25519

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/hash/blake2b256"
	"github.com/andantan/kangaroo/crypto/hash/keccak256"
	"github.com/andantan/kangaroo/crypto/hash/ripemd160"
	"github.com/andantan/kangaroo/crypto/hash/sha256"
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
	addressDerivers := []struct {
		name    string
		deriver hash.AddressDeriver
	}{
		{"SHA256", &sha256.Sha256AddressDeriver{}},
		{"KECCAK256", &keccak256.Keccak256AddressDeriver{}},
		{"RIPEMD160", &ripemd160.Ripemd160AddressDeriver{}},
		{"BLAKE2B256", &blake2b256.Blake2b256AddressDeriver{}},
	}

	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	for _, tc := range addressDerivers {
		t.Run(fmt.Sprintf("with %s address deriver", tc.name), func(t *testing.T) {
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
			address := pubKey.Address(tc.deriver)
			assert.NotNil(t, address)
			assert.Equal(t, hash.AddressLength, len(address.Bytes()))
		})
	}
}

func Test_EdDSA_Ed25519_Signature_Lifecycle(t *testing.T) {
	hashDerivers := []struct {
		name    string
		deriver hash.HashDeriver
	}{
		{"SHA256", &sha256.Sha256HashDeriver{}},
		{"KECCAK256", &keccak256.Keccak256HashDeriver{}},
		{"BLAKE2B256", &blake2b256.Blake2b256HashDeriver{}},
	}

	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
			dataHash := tc.deriver.Derive([]byte("test data"))
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
	hashDerivers := []struct {
		name    string
		deriver hash.HashDeriver
	}{
		{"SHA256", &sha256.Sha256HashDeriver{}},
		{"KECCAK256", &keccak256.Keccak256HashDeriver{}},
		{"BLAKE2B256", &blake2b256.Blake2b256HashDeriver{}},
	}

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
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
