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

type Hash interface {
	Bytes() []byte
	IsZero() bool
	IsValid() bool
	Type() string
	String() string
	ShortString(length int) string
	Equal(other Hash) bool
	Gt(other Hash) bool
	Gte(other Hash) bool
	Lt(other Hash) bool
	Lte(other Hash) bool
}

type HashDeriver interface {
	Derive(data []byte) Hash
}
