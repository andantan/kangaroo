package testutil

import (
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/key/ecdsa/secp256k1"
	"github.com/andantan/kangaroo/crypto/key/ecdsa/secp256r1"
	"github.com/andantan/kangaroo/crypto/key/eddsa/ed25519"
)

type KeySuiteTestCase struct {
	Name  string
	Suite key.KeySuite
}

func GetKeySuiteTestCases() []KeySuiteTestCase {
	return []KeySuiteTestCase{
		{"ECDSA_SECP256R1", &secp256r1.ECDSASecp256r1Suite{}},
		{"ECDSA_SECP256K1", &secp256k1.ECDSASecp256k1Suite{}},
		{"EdDSA_ED25519", &ed25519.EdDSAEd25519Suite{}},
	}
}
