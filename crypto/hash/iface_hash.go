package hash

import "github.com/andantan/kangaroo/types/format"

const (
	HashLength = 32
)

const (
	Sha256Type        = "sha256"
	Keccak256Type     = "keccak256"
	Ripemd160Type     = "ripemd160"
	Blake2b256Type    = "blake2b256"
	PoseidonBN254Type = "poseidon-bn254"
	MimcBN254Type     = "mimc-bn254"
)

type Hash interface {
	format.Byteable
	format.Stringable
	format.StringTypable
	format.Validatable

	IsZero() bool
	ShortString(length int) string
	Equal(other Hash) bool
	Gt(other Hash) bool
	Gte(other Hash) bool
	Lt(other Hash) bool
	Lte(other Hash) bool
}

type HashDeriver interface {
	format.StringTypable

	Derive(data []byte) Hash
}

type Hashable interface {
	Hash(deriver HashDeriver) (Hash, error)
}

type HashSuite interface {
	format.StringTypable

	Deriver() HashDeriver
	HashFromBytes(data []byte) (Hash, error)
}
