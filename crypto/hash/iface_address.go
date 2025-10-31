package hash

const (
	AddressLength    = 20
	AddressHexLength = AddressLength * 2
)

type Address interface {
	Bytes() []byte
	IsZero() bool
	IsValid() bool
	Type() string
	String() string
	ShortString(length int) string
	Equal(other Address) bool
	Gt(other Address) bool
	Gte(other Address) bool
	Lt(other Address) bool
	Lte(other Address) bool
}

type AddressDeriver interface {
	Derive(data []byte) Address
}
