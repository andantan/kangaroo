package core

import (
	"github.com/andantan/kangaroo/core/testutil"
	"github.com/andantan/kangaroo/core/transaction/kangarootransaction"
	_ "github.com/andantan/kangaroo/crypto/all"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func setupTestMatrix(t *testing.T) []struct {
	name      string
	keySuite  key.KeySuite
	hashSuite hash.HashSuite
} {
	secp256r1Suite, err := registry.GetKeySuite("ecdsa-secp256r1")
	require.NoError(t, err)
	secp256k1Suite, err := registry.GetKeySuite("ecdsa-secp256k1")
	require.NoError(t, err)
	ed25519Suite, err := registry.GetKeySuite("eddsa-ed25519")
	require.NoError(t, err)

	sha256Suite, err := registry.GetHashSuite("sha256")
	require.NoError(t, err)
	keccak256Suite, err := registry.GetHashSuite("keccak256")
	require.NoError(t, err)

	return []struct {
		name      string
		keySuite  key.KeySuite
		hashSuite hash.HashSuite
	}{
		{"SECP256R1_with_SHA256", secp256r1Suite, sha256Suite},
		{"SECP256R1_with_KECCAK256", secp256r1Suite, keccak256Suite},
		{"SECP256K1_with_SHA256", secp256k1Suite, sha256Suite},
		{"SECP256K1_with_KECCAK256", secp256k1Suite, keccak256Suite},
		{"ED25519_with_SHA256", ed25519Suite, sha256Suite},
		{"ED25519_with_KECCAK256", ed25519Suite, keccak256Suite},
	}
}

func TestTransactionRegistry_WrapUnwrap_RoundTrip(t *testing.T) {
	testCases := testutil.GetSuitesPairTestCases()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// --- Setup ---
			hasher := tc.HashSuite.Deriver()
			signer, err := tc.KeySuite.GeneratePrivateKey()
			require.NoError(t, err)
			signerAddr := signer.PublicKey().Address(tc.AddressSuite.Deriver())
			assert.Equal(t, hash.AddressLength, len(signerAddr.Bytes()))

			tx := kangarootransaction.NewKangarooTransaction(nil, nil, []byte("kangaroo-transaction"), uint64(1))
			err = tx.Sign(signer, hasher)
			require.NoError(t, err)

			// 2. Bytes round trip
			wrappedTx, err := WrapTransaction(tx)
			require.NoError(t, err)
			unwrappedTx, err := UnwrapTransaction(wrappedTx)
			require.NoError(t, err)

			// 3. compare
			origHash, err := tx.Hash(hasher)
			require.NoError(t, err)
			unwrappedHash, err := unwrappedTx.Hash(hasher)
			require.NoError(t, err)
			assert.True(t, origHash.Equal(unwrappedHash))

			// 4. String round trip
			wrappedString, err := WrapTransactionToString(tx)
			require.NoError(t, err)
			parsedTx, err := UnwrapTransactionFromString(wrappedString)
			require.NoError(t, err)
			parsedHash, err := parsedTx.Hash(hasher)
			require.NoError(t, err)
			assert.True(t, origHash.Equal(parsedHash))

			// 5. verify
			err = unwrappedTx.Verify(hasher)
			assert.NoError(t, err, "unwrapped tx from bytes should be valid")
			err = parsedTx.Verify(hasher)
			assert.NoError(t, err, "unwrapped tx from string should be valid")
		})
	}
}
