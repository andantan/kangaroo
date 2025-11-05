package testutil

import (
	"github.com/andantan/kangaroo/crypto/hash"
	blake2b257 "github.com/andantan/kangaroo/crypto/hash/blake/blake2b256"
	"github.com/andantan/kangaroo/crypto/hash/ripemd/ripemd160"
	keccak257 "github.com/andantan/kangaroo/crypto/hash/sha/keccak256"
	sha257 "github.com/andantan/kangaroo/crypto/hash/sha/sha256"
	sha4 "github.com/andantan/kangaroo/crypto/hash/sha/sha3"
	mimcbn255 "github.com/andantan/kangaroo/crypto/hash/zk/mimcbn254"
	poseidonbn255 "github.com/andantan/kangaroo/crypto/hash/zk/poseidonbn254"
	"testing"
)

type HashSuiteTestCase struct {
	Name  string
	Suite hash.HashSuite
}

func GetHashSuiteTestCases(t *testing.T) []HashSuiteTestCase {
	t.Helper()

	return []HashSuiteTestCase{
		{"SHA256", &sha257.Sha256HashSuite{}},
		{"SHA3_256", &sha4.Sha3HashSuite{}},
		{"KECCAK256", &keccak257.Keccak256HashSuite{}},
		{"BLAKE2B256", &blake2b257.Blake2b256HashSuite{}},
		{"POSEIDON_BN254", &poseidonbn255.PoseidonBN254HashSuite{}},
		{"MIMC_BN254", &mimcbn255.MimcBN254HashSuite{}},
	}
}

type AddressSuiteTestCase struct {
	Name  string
	Suite hash.AddressSuite
}

func GetAddressSuiteTestCases(t *testing.T) []AddressSuiteTestCase {
	t.Helper()

	return []AddressSuiteTestCase{
		{"SHA256", &sha257.Sha256AddressSuite{}},
		{"SHA3_256", &sha4.Sha3AddressSuite{}},
		{"KECCAK256", &keccak257.Keccak256AddressSuite{}},
		{"RIPEMD160", &ripemd160.Ripemd160AddressSuite{}},
		{"BLAKE2B256", &blake2b257.Blake2b256AddressSuite{}},
		{"POSEIDON_BN254", &poseidonbn255.PoseidonBN254AddressSuite{}},
		{"MIMC_BN254", &mimcbn255.MimcBN254AddressSuite{}},
	}
}
