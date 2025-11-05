package testutil

import (
	"github.com/andantan/kangaroo/crypto/key"
	ecdsasecp256k1 "github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	"github.com/andantan/kangaroo/crypto/key/ecdsa/secp256r1"
	"github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
	"github.com/andantan/kangaroo/crypto/key/eddsa/ed448"
	schnorrsecp256k1 "github.com/andantan/kangaroo/crypto/key/schnorr/secp256k1"
	"testing"
)

type KeySuiteTestCase struct {
	Name  string
	Suite key.KeySuite
}

func GetKeySuiteTestCases(t *testing.T) []KeySuiteTestCase {
	t.Helper()

	return []KeySuiteTestCase{
		{"ECDSA_SECP256R1", &secp256r1.ECDSASecp256r1Suite{}},
		{"ECDSA_SECP256K1", &ecdsasecp256k1.ECDSASecp256k1Suite{}},
		{"EdDSA_ED25519", &ed25519.EdDSAEd25519Suite{}},
		{"EdDSA_ED448", &ed448.EdDSAEd448Suite{}},
		{"SCHNORR_SECP256K1", &schnorrsecp256k1.SchnorrSecp256k1Suite{}},
	}
}
