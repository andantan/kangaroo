package testutil

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	hashtestutil "github.com/andantan/kangaroo/crypto/hash/testutil"
	"github.com/andantan/kangaroo/crypto/key"
	keytestutil "github.com/andantan/kangaroo/crypto/key/testutil"
	"testing"
)

type SuitesPairTestCase struct {
	Name         string
	KeySuite     key.KeySuite
	HashSuite    hash.HashSuite
	AddressSuite hash.AddressSuite
}

func GetSuitesPairTestCases(t *testing.T) []SuitesPairTestCase {
	t.Helper()

	keySuites := keytestutil.GetKeySuiteTestCases(t)
	hashSuites := hashtestutil.GetHashSuiteTestCases(t)
	addressSuites := hashtestutil.GetAddressSuiteTestCases(t)

	totalCapacity := len(keySuites) * len(hashSuites) * len(addressSuites)
	tc := make([]SuitesPairTestCase, 0, totalCapacity)

	for _, kSuiteCase := range keySuites {
		for _, hSuiteCase := range hashSuites {
			for _, aSuiteCase := range addressSuites {
				// e.g., "SCHNORR_SECP256K1_Hash-KECCAK256_Addr-RIPEMD160"
				testName := fmt.Sprintf("%s_HASH_%s_ADDRESS_%s",
					kSuiteCase.Name,
					hSuiteCase.Name,
					aSuiteCase.Name,
				)

				newCase := SuitesPairTestCase{
					Name:         testName,
					KeySuite:     kSuiteCase.Suite,
					HashSuite:    hSuiteCase.Suite,
					AddressSuite: aSuiteCase.Suite,
				}

				tc = append(tc, newCase)
			}
		}
	}

	return tc
}
