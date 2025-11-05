package testutil

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/hash/blake2b256"
	"github.com/andantan/kangaroo/crypto/hash/keccak256"
	"github.com/andantan/kangaroo/crypto/hash/mimcbn254"
	"github.com/andantan/kangaroo/crypto/hash/poseidonbn254"
	"github.com/andantan/kangaroo/crypto/hash/ripemd160"
	"github.com/andantan/kangaroo/crypto/hash/sha256"
	"github.com/andantan/kangaroo/crypto/hash/sha3"
)

type HashSuiteTestCase struct {
	Name  string
	Suite hash.HashSuite
}

type AddressSuiteTestCase struct {
	Name  string
	Suite hash.AddressSuite
}

func GetHashSuiteTestCases() []HashSuiteTestCase {
	return []HashSuiteTestCase{
		{"SHA256", &sha256.Sha256HashSuite{}},
		{"SHA3_256", &sha3.Sha3HashSuite{}},
		{"KECCAK256", &keccak256.Keccak256HashSuite{}},
		{"BLAKE2B256", &blake2b256.Blake2b256HashSuite{}},
		{"POSEIDON_BN254", &poseidonbn254.PoseidonBN254HashSuite{}},
		{"MIMC_BN254", &mimcbn254.MimcBN254HashSuite{}},
	}
}

func GetAddressSuiteTestCases() []AddressSuiteTestCase {
	return []AddressSuiteTestCase{
		{"SHA256", &sha256.Sha256AddressSuite{}},
		{"SHA3_256", &sha3.Sha3AddressSuite{}},
		{"KECCAK256", &keccak256.Keccak256AddressSuite{}},
		{"RIPEMD160", &ripemd160.Ripemd160AddressSuite{}},
		{"BLAKE2B256", &blake2b256.Blake2b256AddressSuite{}},
		{"POSEIDON_BN254", &poseidonbn254.PoseidonBN254AddressSuite{}},
		{"MIMC_BN254", &mimcbn254.MimcBN254AddressSuite{}},
	}
}
