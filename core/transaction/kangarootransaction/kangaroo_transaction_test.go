package kangarootransaction

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/transaction"
	_ "github.com/andantan/kangaroo/crypto/all"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/testutil"
	kangarootxpb "github.com/andantan/kangaroo/proto/core/transaction/pb"
	"github.com/andantan/kangaroo/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func newTestKangarooTransaction(d []byte, n int) *KangarooTransaction {
	return NewKangarooTransaction(nil, nil, d, uint64(n))
}

func TestKangarooTransaction_FullLifecycle(t *testing.T) {
	testCases := testutil.GetSuitesPairTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// --- 1. create and sign ---
			tx := newTestKangarooTransaction([]byte("test_data"), 1)
			t.Logf("%s\n", tx)
			assert.Equal(t, transaction.KangarooTransactionType, tx.Type())

			signer, err := tc.KeySuite.GeneratePrivateKey()
			require.NoError(t, err)
			signerAddr := signer.PublicKey().Address(tc.AddressSuite.Deriver())
			assert.Equal(t, hash.AddressLength, len(signerAddr.Bytes()))

			err = tx.Sign(signer, tc.HashSuite.Deriver())
			require.NoError(t, err)
			assert.NotNil(t, tx.Signer)
			assert.NotNil(t, tx.Signature)
			assert.Equal(t, tx.Signer.Type(), tx.Signature.Type())
			assert.True(t, tx.Signer.IsValid())
			assert.True(t, tx.Signature.IsValid())
			assert.True(t, tx.Signer.Equal(signer.PublicKey()))

			// --- 2. verify - success case ---
			err = tx.Verify(tc.HashSuite.Deriver())
			assert.NoError(t, err, "correctly signed transaction should verify successfully")

			// --- 3. Hashable ---
			// 3a. hash for signing
			signingHash, err := tx.HashForSigning(tc.HashSuite.Deriver())
			require.NoError(t, err)
			assert.False(t, signingHash.IsZero())

			// 3b. hash for txID (including signature)
			txIDHash, err := tx.Hash(tc.HashSuite.Deriver())
			require.NoError(t, err)
			assert.False(t, txIDHash.IsZero())

			// 3c. must different
			assert.NotEqual(t, signingHash, txIDHash, "TxID hash and signing hash must be different")

			// --- 4. ProtoCodec (Round Trip) ---
			// 4a. Marshall (Encode)
			encodedBytes, err := codec.EncodeProto(tx)
			require.NoError(t, err)
			assert.NotEmpty(t, encodedBytes)

			// 4b. UnMarshall (Decode)
			newTx := new(KangarooTransaction)
			err = codec.DecodeProto(encodedBytes, newTx)
			require.NoError(t, err)
			assert.NotNil(t, newTx.Signer)
			assert.NotNil(t, newTx.Signature)
			assert.Equal(t, newTx.Signer.Type(), newTx.Signature.Type())
			assert.True(t, newTx.Signer.IsValid())
			assert.True(t, newTx.Signature.IsValid())
			assert.True(t, newTx.Signer.Equal(signer.PublicKey()))

			// 4c. compare
			assert.Equal(t, tx.Data, newTx.Data)
			assert.Equal(t, tx.Nonce, newTx.Nonce)
			assert.True(t, tx.Signer.Equal(newTx.Signer), "public keys should be equal after round trip")
			assert.True(t, tx.Signature.Equal(newTx.Signature), "signatures should be equal after round trip")

			err = newTx.Verify(tc.HashSuite.Deriver())
			assert.NoError(t, err, "restored transaction should also verify successfully")
		})
	}
}

func TestKangarooTransaction_Verify_Failures(t *testing.T) {
	// secp256k1 + blake2b256
	keySuite, _ := registry.GetKeySuite("ecdsa-secp256k1")
	hashSuite, _ := registry.GetHashSuite("blake2b256")
	signer, _ := keySuite.GeneratePrivateKey()

	// original transaction
	getValidTx := func() *KangarooTransaction {
		tx := newTestKangarooTransaction([]byte("valid data"), 1)
		err := tx.Sign(signer, hashSuite.Deriver())
		require.NoError(t, err)
		assert.NotNil(t, tx.Signer)
		assert.NotNil(t, tx.Signature)
		return tx
	}

	t.Run("should fail if not signed (nil signature)", func(t *testing.T) {
		tx := newTestKangarooTransaction([]byte("data"), 1)
		tx.Signer = signer.PublicKey() // nil signature
		assert.NotNil(t, tx.Signer)
		assert.Nil(t, tx.Signature)
		err := tx.Verify(hashSuite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not signed")
	})

	t.Run("should fail if not signed (nil signer)", func(t *testing.T) {
		tx := getValidTx()
		tx.Signer = nil // no signer
		assert.Nil(t, tx.Signer)
		err := tx.Verify(hashSuite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not signed")
	})

	t.Run("should fail if data is tampered", func(t *testing.T) {
		tx := getValidTx()
		tx.Data = []byte("tampered data!") // tampering data
		err := tx.Verify(hashSuite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("should fail if nonce is tampered", func(t *testing.T) {
		tx := getValidTx()
		tx.Nonce = 99 // tampering nonce
		err := tx.Verify(hashSuite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("should fail if signer is tampered", func(t *testing.T) {
		tx := getValidTx()
		otherSigner, _ := keySuite.GeneratePrivateKey()
		tx.Signer = otherSigner.PublicKey() // tamper signer
		err := tx.Verify(hashSuite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("should fail with different algorithm types", func(t *testing.T) {
		tx := getValidTx()
		// change algorithm to eddsa-ed25519
		edSuite, _ := registry.GetKeySuite("eddsa-ed25519")
		otherSigner, _ := edSuite.GeneratePrivateKey()
		tx.Signer = otherSigner.PublicKey()

		err := tx.Verify(hashSuite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key type (eddsa-ed25519) does not match signature type (ecdsa-secp256k1)")
	})
}

func TestKangarooTransaction_Hash_Failures(t *testing.T) {
	suite, _ := registry.GetHashSuite("sha256")

	t.Run("should fail to hash unsigned transaction", func(t *testing.T) {
		tx := newTestKangarooTransaction([]byte("data"), 1) // not signed
		_, err := tx.Hash(suite.Deriver())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot hash unsigned transaction")
	})
}

func TestKangarooTransaction_With_ToAddress_And_Value(t *testing.T) {
	// ed25519 + keccak256
	keySuite, _ := registry.GetKeySuite("eddsa-ed25519")
	hashSuite, _ := registry.GetHashSuite("keccak256")
	addressSuite, _ := registry.GetAddressSuite("blake2b256")
	hasher := hashSuite.Deriver()

	signer, err := keySuite.GeneratePrivateKey()
	require.NoError(t, err)
	recipientPubKey, err := keySuite.GeneratePrivateKey()
	require.NoError(t, err)
	toAddress := recipientPubKey.PublicKey().Address(addressSuite.Deriver())

	tx := NewKangarooTransaction(
		toAddress,
		big.NewInt(1000000000),
		[]byte("with value data"),
		1,
	)

	// signature
	err = tx.Sign(signer, hasher)
	require.NoError(t, err)

	// verify
	err = tx.Verify(hasher)
	require.NoError(t, err, "tx with value and address should verify successfully")

	// 6. ProtoCodec round trip
	encodedBytes, err := codec.EncodeProto(tx)
	require.NoError(t, err)

	newTx := new(KangarooTransaction)
	err = codec.DecodeProto(encodedBytes, newTx)
	require.NoError(t, err)

	assert.True(t, tx.ToAddress.Equal(newTx.ToAddress), "ToAddress should be equal after round trip")
	assert.Equal(t, tx.Value, newTx.Value, "Value should be equal after round trip")

	err = newTx.Verify(hasher)
	assert.NoError(t, err, "restored tx with value and address should also verify")
}

func TestKangarooTransaction_FromProto_Failures(t *testing.T) {
	// unknown public key prefix
	invalidPublicKeyBytes := []byte{0x99, 0x01, 0x02, 0x03}

	// unknown signature prefix
	invalidSignatureBytes := []byte{0xAA, 0x01, 0x02, 0x03}

	// unknown address prefix
	invalidAddressBytes := []byte{0xBB, 0x01, 0x02, 0x03}

	t.Run("should fail with invalid signer bytes", func(t *testing.T) {
		pbTx := &kangarootxpb.KangarooTransaction{
			Signer: invalidPublicKeyBytes, // tampering public key
		}
		tx := new(KangarooTransaction)
		err := tx.FromProto(pbTx)
		assert.Error(t, err)
	})

	t.Run("should fail with invalid signature bytes", func(t *testing.T) {
		pbTx := &kangarootxpb.KangarooTransaction{
			Signature: invalidSignatureBytes, // tampering signature
		}
		tx := new(KangarooTransaction)
		err := tx.FromProto(pbTx)
		assert.Error(t, err)
	})

	t.Run("should fail with invalid address bytes", func(t *testing.T) {
		pbTx := &kangarootxpb.KangarooTransaction{
			ToAddress: invalidAddressBytes, // tampering address
		}
		tx := new(KangarooTransaction)
		err := tx.FromProto(pbTx)
		assert.Error(t, err)
	})
}
