package kangaroobody

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/core/transaction"
	"github.com/andantan/kangaroo/core/transaction/kangarootransaction"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/testutil"
	"github.com/andantan/kangaroo/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func createSignedTx(t *testing.T, data string, nonce uint64, signer key.PrivateKey, deriver hash.HashDeriver) transaction.Transaction {
	tx := kangarootransaction.NewKangarooTransaction(nil, nil, []byte(data), nonce)
	err := tx.Sign(signer, deriver)
	require.NoError(t, err)
	assert.NotNil(t, tx.Signer)
	assert.NotNil(t, tx.Signature)
	return tx
}

func TestKangarooBody_FullLifecycle(t *testing.T) {
	testCases := testutil.GetSuitesPairTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// --- Setup ---
			hasher := tc.HashSuite.Deriver()
			signer, err := tc.KeySuite.GeneratePrivateKey()
			require.NoError(t, err)
			signerAddr := signer.PublicKey().Address(tc.AddressSuite.Deriver())
			assert.Equal(t, hash.AddressLength, len(signerAddr.Bytes()))

			// --- 1. Create Body (odd weight) ---
			tx1 := createSignedTx(t, "tx1", 1, signer, hasher)
			tx2 := createSignedTx(t, "tx2", 2, signer, hasher)
			tx3 := createSignedTx(t, "tx3", 3, signer, hasher)

			originalBody := NewKangarooBody([]transaction.Transaction{tx1, tx2, tx3})

			assert.Equal(t, uint64(3), originalBody.GetWeight())
			assert.Len(t, originalBody.GetTransactions(), 3)
			assert.Equal(t, block.KangarooBodyType, originalBody.Type())
			assert.NotEmpty(t, originalBody.String())

			// --- 2. Hash (Merkle Root) Test ---
			merkleRoot, err := originalBody.Hash(hasher)
			require.NoError(t, err)
			assert.False(t, merkleRoot.IsZero())

			// --- 3. ProtoCodec (Round Trip) ---
			// 3a. Marshall (Encode) - ToProto가 WrapTransaction을 호출
			encodedBytes, err := codec.EncodeProto(originalBody)
			require.NoError(t, err)
			assert.NotEmpty(t, encodedBytes)

			// 3b. UnMarshall (Decode) - FromProto가 UnwrapTransaction을 호출
			newBody := new(KangarooBody)
			err = codec.DecodeProto(encodedBytes, newBody)
			require.NoError(t, err)

			// --- 4. Compare restored object ---
			assert.Equal(t, originalBody.GetWeight(), newBody.GetWeight())
			require.Len(t, newBody.GetTransactions(), 3)

			// 4a. recovered body hash compare
			newMerkleRoot, err := newBody.Hash(hasher)
			require.NoError(t, err)
			assert.True(t, merkleRoot.Equal(newMerkleRoot), "Merkle root should be deterministic")

			// 4b. recovered txx hash compare
			tx1hashOrig, err := tx1.Hash(hasher)
			require.NoError(t, err)
			tx1hashNew, err := newBody.GetTransactions()[0].Hash(hasher)
			require.NoError(t, err)
			assert.True(t, tx1hashOrig.Equal(tx1hashNew))
		})
	}
}

func TestKangarooBody_EdgeCases(t *testing.T) {
	keySuite, err := registry.GetKeySuite("ecdsa-secp256k1")
	require.NoError(t, err)
	hashSuite, err := registry.GetHashSuite("sha256")
	require.NoError(t, err)
	hasher := hashSuite.Deriver()

	t.Run("Body with 0 Transactions (Empty Body)", func(t *testing.T) {
		emptyBody := NewKangarooBody(nil)

		// 1. Hash
		merkleRoot, err := emptyBody.Hash(hasher)
		require.NoError(t, err)
		assert.True(t, merkleRoot.IsZero(), "Hash of empty body should be ZeroHash")

		// 2. ProtoCodec round trip
		encodedBytes, err := codec.EncodeProto(emptyBody)
		require.NoError(t, err)

		newBody := new(KangarooBody)
		err = codec.DecodeProto(encodedBytes, newBody)
		require.NoError(t, err)
		assert.Len(t, newBody.GetTransactions(), 0)
	})

	t.Run("Body with 1 Transaction", func(t *testing.T) {
		signer, _ := keySuite.GeneratePrivateKey()
		tx1 := createSignedTx(t, "tx1", 1, signer, hasher)

		singleTxBody := NewKangarooBody([]transaction.Transaction{tx1})

		// 1. Hash
		// if len(txx) == 1, then merkleroot equals tx hash.
		tx1Hash, err := tx1.Hash(hasher)
		require.NoError(t, err)
		merkleRoot, err := singleTxBody.Hash(hasher)
		require.NoError(t, err)
		assert.True(t, tx1Hash.Equal(merkleRoot), "Merkle root of 1 tx should be the tx hash itself")

		// 2. ProtoCodec round trip
		encodedBytes, err := codec.EncodeProto(singleTxBody)
		require.NoError(t, err)

		newBody := new(KangarooBody)
		err = codec.DecodeProto(encodedBytes, newBody)
		require.NoError(t, err)
		require.Len(t, newBody.GetTransactions(), 1)

		newTx1Hash, err := newBody.GetTransactions()[0].Hash(hasher)
		require.NoError(t, err)
		assert.True(t, tx1Hash.Equal(newTx1Hash))
	})
}
