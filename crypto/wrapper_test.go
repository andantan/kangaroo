package crypto

import (
	"fmt"
	_ "github.com/andantan/kangaroo/crypto/all"
	hashtestutil "github.com/andantan/kangaroo/crypto/hash/testutil"
	keytestutil "github.com/andantan/kangaroo/crypto/key/testutil"
	"github.com/andantan/kangaroo/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"testing"
)

func TestKeyWrapper_WrapUnwrap_RoundTrip(t *testing.T) {
	keySuites := keytestutil.GetKeySuiteTestCases(t)

	var keySuiteNames []string
	for _, s := range keySuites {
		keySuiteNames = append(keySuiteNames, s.Suite.Type())
	}

	for _, suiteName := range keySuiteNames {
		t.Run(fmt.Sprintf("%s key wrapper wrap & unwrap round trip", suiteName), func(t *testing.T) {
			// --- 1. Setup ---
			suite, err := registry.GetKeySuite(suiteName)
			require.NoError(t, err)
			privKey, err := suite.GeneratePrivateKey()
			require.NoError(t, err)
			pubKey := privKey.PublicKey()
			hash := blake2b.Sum256([]byte("test data"))
			sig, err := privKey.Sign(hash[:])
			require.NoError(t, err)

			// --- 2. PrivateKey round trip test ---
			// a. Bytes (Wrap -> Unwrap)
			wrappedPriv, err := WrapPrivateKey(privKey)
			require.NoError(t, err)
			unwrappedPriv, err := UnwrapPrivateKey(wrappedPriv)
			require.NoError(t, err)
			reroundUnwrappedPriv, err := WrapPrivateKey(unwrappedPriv)
			assert.Equal(t, wrappedPriv, reroundUnwrappedPriv)

			// b. String (Wrap -> String -> Parse)
			wrappedPrivString, err := WrapPrivateKeyToString(privKey)
			require.NoError(t, err)
			parsedPriv, err := UnwrapPrivateKeyFromString(wrappedPrivString)
			require.NoError(t, err)
			reroundParsedPriv, err := WrapPrivateKey(parsedPriv)
			assert.Equal(t, wrappedPriv, reroundParsedPriv)

			// --- 3. PublicKey round trip test ---
			// a. Bytes (Wrap -> Unwrap)
			wrappedPub, err := WrapPublicKey(pubKey)
			require.NoError(t, err)
			unwrappedPub, err := UnwrapPublicKey(wrappedPub)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(unwrappedPub))

			// b. String (Wrap -> String -> Parse)
			wrappedPubString, err := WrapPublicKeyToString(pubKey)
			require.NoError(t, err)
			parsedPub, err := UnwrapPublicKeyFromString(wrappedPubString)
			require.NoError(t, err)
			assert.True(t, pubKey.Equal(parsedPub))

			// --- 4. Signature round trip test ---
			// a. Bytes (Wrap -> Unwrap)
			wrappedSig, err := WrapSignature(sig)
			require.NoError(t, err)
			unwrappedSig, err := UnwrapSignature(wrappedSig)
			require.NoError(t, err)
			assert.True(t, sig.Equal(unwrappedSig))

			// b. String (Wrap -> String -> Parse)
			wrappedSigString, err := WrapSignatureToString(sig)
			require.NoError(t, err)
			parsedSig, err := UnwrapSignatureFromString(wrappedSigString)
			require.NoError(t, err)
			assert.True(t, sig.Equal(parsedSig))
		})
	}
}

func TestHashWrapper_AddressWrapper_WrapUnwrap_RoundTrip(t *testing.T) {
	// --- 1. setup ---
	hashSuites := hashtestutil.GetHashSuiteTestCases(t)
	var hashSuiteNames []string
	for _, s := range hashSuites {
		hashSuiteNames = append(hashSuiteNames, s.Suite.Type())
	}

	addressSuites := hashtestutil.GetAddressSuiteTestCases(t)
	var addressSuitesNames []string
	for _, s := range addressSuites {
		addressSuitesNames = append(addressSuitesNames, s.Suite.Type())
	}

	testData := []byte("test data for hashing")

	// --- 2. Hash round trip test ---
	for _, suiteName := range hashSuiteNames {
		t.Run(fmt.Sprintf("%s hash wrapper wrap & unwrap round trip", suiteName), func(t *testing.T) {
			suite, err := registry.GetHashSuite(suiteName)
			require.NoError(t, err)
			hasher := suite.Deriver()
			hashObj := hasher.Derive(testData)

			wrappedHash, err := WrapHash(hashObj)
			require.NoError(t, err)
			unwrappedHash, err := UnwrapHash(wrappedHash)
			require.NoError(t, err)
			assert.True(t, hashObj.Equal(unwrappedHash))

			wrappedHashString, err := WrapHashToString(hashObj)
			require.NoError(t, err)
			parsedHash, err := UnwrapHashFromString(wrappedHashString)
			require.NoError(t, err)
			assert.True(t, hashObj.Equal(parsedHash))
		})
	}

	// --- 3. Address round trip test ---
	for _, suiteName := range addressSuitesNames {
		t.Run(fmt.Sprintf("%s address wrapper wrap & unwrap round trip", suiteName), func(t *testing.T) {
			suite, err := registry.GetAddressSuite(suiteName)
			require.NoError(t, err)
			deriver := suite.Deriver()
			addrObj := deriver.Derive(testData)

			wrappedAddr, err := WrapAddress(addrObj)
			require.NoError(t, err)
			unwrappedAddr, err := UnwrapAddress(wrappedAddr)
			require.NoError(t, err)
			assert.True(t, addrObj.Equal(unwrappedAddr))

			wrappedAddressString, err := WrapAddressToString(addrObj)
			require.NoError(t, err)
			parsedAddr, err := UnwrapAddressFromString(wrappedAddressString)
			require.NoError(t, err)
			assert.True(t, addrObj.Equal(parsedAddr))
		})
	}
}

func TestUnwrap_FailureCases(t *testing.T) {
	t.Run("should fail with data too short", func(t *testing.T) {
		_, err := UnwrapPublicKey([]byte{}) // no prefix
		assert.Error(t, err)
	})

	t.Run("should fail with unknown prefix", func(t *testing.T) {
		invalidData := make([]byte, 40)
		invalidData[0] = 0xAA // not registered prefix

		_, err := UnwrapPublicKey(invalidData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown key type prefix")

		_, err = UnwrapHash(invalidData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown hash type prefix")
	})

	t.Run("should fail with invalid hex string", func(t *testing.T) {
		_, err := UnwrapPublicKeyFromString("0xNOT-A-HEX-STRING")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid public-key hex string")
	})
}
