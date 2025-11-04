package hash

import "github.com/andantan/kangaroo/types/format"

const (
	AddressLength    = 20
	AddressHexLength = AddressLength * 2
)

type Address interface {
	format.Byteable
	format.Stringable
	format.StringTypable
	format.Validatable

	IsZero() bool
	ShortString(length int) string
	Equal(other Address) bool
	Gt(other Address) bool
	Gte(other Address) bool
	Lt(other Address) bool
	Lte(other Address) bool
}

type AddressDeriver interface {
	format.StringTypable

	Derive(data []byte) Address
}

type Addressable interface {
	Address(deriver AddressDeriver) (Address, error)
}

type AddressSuite interface {
	format.StringTypable

	Deriver() AddressDeriver
	AddressFromBytes(data []byte) (Address, error)
}
