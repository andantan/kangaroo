package p256

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookeccak256 "github.com/andantan/kangaroo/crypto/hash/keccak256"
	kangarooripemd160 "github.com/andantan/kangaroo/crypto/hash/ripemd160"
	kangaroosha256 "github.com/andantan/kangaroo/crypto/hash/sha256"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_ECDSA_P256_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, kangarooecdsa.ECDSAP256Type, privKey.Type())

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

func Test_ECDSA_P256_PublicKey_Lifecycle(t *testing.T) {
	derivers := []struct {
		name    string
		deriver kangaroohash.AddressDeriver
	}{
		{"SHA256", &kangaroosha256.Sha256AddressDeriver{}},
		{"KECCAK256", &kangarookeccak256.Keccak256AddressDeriver{}},
		{"RIPEMD160", &kangarooripemd160.Ripemd160AddressDeriver{}},
	}

	privKey, err := GenerateECDSAP256PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	for _, tc := range derivers {
		t.Run(fmt.Sprintf("with %s address deriver", tc.name), func(t *testing.T) {
			// 1. Validation and Type Check
			assert.True(t, pubKey.IsValid())
			assert.Equal(t, kangarooecdsa.ECDSAP256Type, pubKey.Type())

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

			// 4. Address Derivation using the current Deriver from the table
			address := pubKey.Address(tc.deriver)
			assert.NotNil(t, address)
			assert.Equal(t, kangaroohash.AddressLength, len(address.Bytes()))
		})
	}
}

func Test_ECDSA_P256_Signature_Lifecycle(t *testing.T) {
	hashDerivers := []struct {
		name    string
		deriver kangaroohash.HashDeriver
	}{
		{"SHA256", &kangaroosha256.Sha256HashDeriver{}},
		{"KECCAK256", &kangarookeccak256.Keccak256HashDeriver{}},
	}

	privKey, _ := GenerateECDSAP256PrivateKey()

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
			dataHash := tc.deriver.Derive([]byte("test data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			assert.True(t, signature.IsValid(), "Signature should be valid (pass Low-S check)")
			assert.Equal(t, kangarooecdsa.ECDSAP256Type, signature.Type())

			sigBytes := signature.Bytes()
			reloadedSig, err := ECDSAP256SignatureFromBytes(sigBytes)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSig))

			sigString := signature.String()
			reloadedSigFromString, err := ECDSAP256SignatureFromString(sigString)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSigFromString))
		})
	}
}

func Test_ECDSA_P256_Signature_Verify(t *testing.T) {
	hashDerivers := []struct {
		name    string
		deriver kangaroohash.HashDeriver
	}{
		{"SHA256", &kangaroosha256.Sha256HashDeriver{}},
		{"KECCAK256", &kangarookeccak256.Keccak256HashDeriver{}},
	}

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
			// --- Setup ---
			privKey, err := GenerateECDSAP256PrivateKey()
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
				otherPrivKey, err := GenerateECDSAP256PrivateKey()
				assert.NoError(t, err)
				otherPubKey := otherPrivKey.PublicKey()
				assert.False(t, signature.Verify(otherPubKey, dataHash.Bytes()))
			})

			t.Run("Verification with invalid public key should fail", func(t *testing.T) {
				invalidPubKeyBytes := make([]byte, kangarooecdsa.ECDSAPublicKeyBytesLength)
				invalidPubKey, err := ECDSAP256PublicKeyFromBytes(invalidPubKeyBytes)
				assert.Error(t, err)
				assert.False(t, signature.Verify(invalidPubKey, dataHash.Bytes()))
			})
		})
	}
}
