package hash

const (
	HashLength    = 32
	HashHexLength = HashLength * 2
)

const (
	Sha256Type    = "sha256"
	Keccak256Type = "keccak256"
	Ripemd160Type = "ripemd160"
)

type Hashable interface {
	Bytes() []byte
	IsZero() bool
	IsValid() bool
	Type() string
	String() string
	ShortString(length int) string
	Equal(hash Hashable) bool
	Gt(hash Hashable) bool
	Gte(hash Hashable) bool
	Lt(hash Hashable) bool
	Lte(hash Hashable) bool
}

type HashDeriver interface {
	Derive(data []byte) Hashable
}
