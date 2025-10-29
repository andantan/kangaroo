package ed25519

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarookeccak256 "github.com/andantan/kangaroo/crypto/hash/keccak256"
	kangarooripemd160 "github.com/andantan/kangaroo/crypto/hash/ripemd160"
	kangaroosha256 "github.com/andantan/kangaroo/crypto/hash/sha256"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_EdDSA_Ed25519_PrivateKey_Lifecycle(t *testing.T) {
	// 1. Generation
	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	assert.True(t, privKey.IsValid())
	assert.Equal(t, kangarooeddsa.EdDSAEd25519Type, privKey.Type())

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

func Test_EdDSA_Ed25519_PublicKey_Lifecycle(t *testing.T) {
	// 1. 테스트할 AddressDeriver들을 테이블로 정의하고 직접 인스턴스화합니다.
	addressDerivers := []struct {
		name    string
		deriver kangaroohash.AddressDeriver
	}{
		{"SHA256", &kangaroosha256.Sha256AddressDeriver{}},
		{"KECCAK256", &kangarookeccak256.Keccak256AddressDeriver{}},
		{"RIPEMD160", &kangarooripemd160.Ripemd160AddressDeriver{}},
	}

	privKey, err := GenerateEdDSAEd25519PrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey()

	// 2. 루프를 돌며 각 Deriver에 대해 하위 테스트(subtest)를 실행합니다.
	for _, tc := range addressDerivers {
		t.Run(fmt.Sprintf("with %s address deriver", tc.name), func(t *testing.T) {
			assert.True(t, pubKey.IsValid())
			assert.Equal(t, kangarooeddsa.EdDSAEd25519Type, pubKey.Type())

			pubKeyBytes := pubKey.Bytes()
			reloadedPubKey, err := EdDSAEd25519PublicKeyFromBytes(pubKeyBytes)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(reloadedPubKey))

			pubKeyString := pubKey.String()
			reloadedPubKeyFromString, err := EdDSAEd25519PublicKeyFromString(pubKeyString)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(reloadedPubKeyFromString))

			address := pubKey.Address(tc.deriver)
			assert.NotNil(t, address)
			assert.Equal(t, kangaroohash.AddressLength, len(address.Bytes()))
		})
	}
}

// Signature 생명주기 테스트를 테이블 주도 방식으로 통합합니다.
func Test_EdDSA_Ed25519_Signature_Lifecycle(t *testing.T) {
	hashDerivers := []struct {
		name    string
		deriver kangaroohash.HashDeriver
	}{
		{"SHA256", &kangaroosha256.Sha256HashDeriver{}},
		{"KECCAK256", &kangarookeccak256.Keccak256HashDeriver{}},
	}

	privKey, _ := GenerateEdDSAEd25519PrivateKey()

	for _, tc := range hashDerivers {
		t.Run(fmt.Sprintf("with %s hash", tc.name), func(t *testing.T) {
			dataHash := tc.deriver.Derive([]byte("test data"))
			signature, err := privKey.Sign(dataHash.Bytes())
			require.NoError(t, err)

			assert.True(t, signature.IsValid())
			assert.Equal(t, kangarooeddsa.EdDSAEd25519Type, signature.Type())

			sigBytes := signature.Bytes()
			reloadedSig, err := EdDSAEd25519SignatureFromBytes(sigBytes)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSig))

			sigString := signature.String()
			reloadedSigFromString, err := EdDSAEd25519SignatureFromString(sigString)
			require.NoError(t, err)
			assert.True(t, signature.Equal(reloadedSigFromString))
		})
	}
}

func Test_EdDSA_Ed25519_Signature_Verify(t *testing.T) {
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
			privKey, err := GenerateEdDSAEd25519PrivateKey()
			require.NoError(t, err)
			pubKey := privKey.PublicKey()

			// Ed25519는 해시가 아닌 원본 데이터를 직접 서명하고 검증합니다.
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
				invalidPubKeyBytes := make([]byte, kangarooeddsa.EdDSAPublicKeyBytesLength)
				invalidPubKey, err := EdDSAEd25519PublicKeyFromBytes(invalidPubKeyBytes)
				assert.NoError(t, err) // 길이만 맞으면 생성은 성공
				assert.False(t, signature.Verify(invalidPubKey, correctData))
			})
		})
	}
}
