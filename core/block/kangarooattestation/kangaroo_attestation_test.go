package kangarooattestation

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/testutil"
	"github.com/andantan/kangaroo/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestKangarooAttestation_FullLifecycle(t *testing.T) {
	testCases := testutil.GetSuitesPairTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			signer, err := tc.KeySuite.GeneratePrivateKey()
			require.NoError(t, err)

			digest := tc.HashSuite.Deriver().Derive([]byte("test_block_digest"))

			signature, err := signer.Sign(digest.Bytes())
			require.NoError(t, err)
			signerAddr := signer.PublicKey().Address(tc.AddressSuite.Deriver())
			assert.Equal(t, hash.AddressLength, len(signerAddr.Bytes()))

			att := NewKangarooAttestation(digest, signer.PublicKey(), signature)
			t.Logf("%s\n", att)

			assert.Equal(t, block.KangarooAttestationType, att.Type())
			assert.True(t, att.GetBlockID().Equal(digest))
			assert.True(t, att.GetSigner().Equal(signer.PublicKey()))
			assert.True(t, att.GetSignature().Equal(signature))

			assert.True(t, att.Verify(), "correctly signed attestation should verify successfully")

			encodedBytes, err := codec.EncodeProto(att)
			require.NoError(t, err)
			assert.NotEmpty(t, encodedBytes)

			// 4b. UnMarshall (Decode)
			newAtt := new(KangarooAttestation)
			err = codec.DecodeProto(encodedBytes, newAtt)
			require.NoError(t, err)

			// 4c. compare
			assert.True(t, att.GetBlockID().Equal(newAtt.GetBlockID()))
			assert.True(t, att.GetSigner().Equal(newAtt.GetSigner()))
			assert.True(t, att.GetSignature().Equal(newAtt.GetSignature()))

			// 4d. restored object must be valid
			assert.True(t, newAtt.Verify(), "restored attestation should also verify successfully")
		})
	}
}

func TestKangarooAttestation_Verify_Failures(t *testing.T) {
	// secp256k1 + sha256
	keySuite, err := registry.GetKeySuite("ecdsa-secp256k1")
	require.NoError(t, err)
	hashSuite, err := registry.GetHashSuite("sha256")
	require.NoError(t, err)
	hasher := hashSuite.Deriver()
	signer, err := keySuite.GeneratePrivateKey()
	require.NoError(t, err)

	// original attestation
	getValidAtt := func() *KangarooAttestation {
		digest := hasher.Derive([]byte("valid_digest"))
		sig, err := signer.Sign(digest.Bytes())
		require.NoError(t, err)
		return NewKangarooAttestation(digest, signer.PublicKey(), sig)
	}

	t.Run("should fail if signature is nil", func(t *testing.T) {
		att := getValidAtt()
		att.Signature = nil
		assert.False(t, att.Verify())
	})

	t.Run("should fail if signer is nil", func(t *testing.T) {
		att := getValidAtt()
		att.Signer = nil
		assert.False(t, att.Verify())
	})

	t.Run("should fail if digest is tampered", func(t *testing.T) {
		att := getValidAtt()
		att.Digest = hasher.Derive([]byte("tampered_digest"))
		assert.False(t, att.Verify())
	})

	t.Run("should fail if signer is tampered", func(t *testing.T) {
		att := getValidAtt()
		otherSigner, err := keySuite.GeneratePrivateKey()
		require.NoError(t, err)
		att.Signer = otherSigner.PublicKey()
		assert.False(t, att.Verify())
	})

	t.Run("should fail with different algorithm types", func(t *testing.T) {
		att := getValidAtt() // secp256k1
		edSuite, err := registry.GetKeySuite("eddsa-ed25519")
		require.NoError(t, err)
		otherSigner, err := edSuite.GeneratePrivateKey()
		require.NoError(t, err)
		att.Signer = otherSigner.PublicKey()

		assert.False(t, att.Verify())
	})
}

func TestKangarooAttestation_Wrapper_RoundTrip(t *testing.T) {
	testCases := testutil.GetSuitesPairTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// --- Setup ---
			hasher := tc.HashSuite.Deriver()
			signer, err := tc.KeySuite.GeneratePrivateKey()
			require.NoError(t, err)

			digest := hasher.Derive([]byte("test_digest"))
			sig, err := signer.Sign(digest.Bytes())
			require.NoError(t, err)

			att := NewKangarooAttestation(digest, signer.PublicKey(), sig)
			t.Logf("%s\n", att)
			assert.True(t, att.Verify())

			// 2. Bytes round trip
			wrappedAtt, err := wrapper.WrapAttestation(att)
			require.NoError(t, err)
			unwrappedAtt, err := wrapper.UnwrapAttestation(wrappedAtt)
			require.NoError(t, err)
			assert.True(t, unwrappedAtt.Verify())

			// 3. Compare
			assert.True(t, att.GetBlockID().Equal(unwrappedAtt.GetBlockID()))
			assert.True(t, att.GetSigner().Equal(unwrappedAtt.GetSigner()))
			assert.True(t, att.GetSignature().Equal(unwrappedAtt.GetSignature()))

			// 4. String round trip
			wrappedString, err := wrapper.WrapAttestationToString(att)
			require.NoError(t, err)
			parsedAtt, err := wrapper.UnwrapAttestationFromString(wrappedString)
			require.NoError(t, err)
			assert.True(t, parsedAtt.Verify())
			assert.True(t, att.GetBlockID().Equal(parsedAtt.GetBlockID()))
			assert.True(t, att.GetSigner().Equal(parsedAtt.GetSigner()))
			assert.True(t, att.GetSignature().Equal(parsedAtt.GetSignature()))
		})
	}
}
