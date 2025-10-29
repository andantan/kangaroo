package hash

const (
	AddressLength    = 20
	AddressHexLength = AddressLength * 2
)

type Addressable interface {
	Bytes() []byte
	IsZero() bool
	IsValid() bool
	Type() string
	String() string
	ShortString(length int) string
	Equal(hash Addressable) bool
	Gt(hash Addressable) bool
	Gte(hash Addressable) bool
	Lt(hash Addressable) bool
	Lte(hash Addressable) bool
}

type AddressDeriver interface {
	Derive(data []byte) Addressable
}
