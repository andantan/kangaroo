package hash

import "github.com/andantan/kangaroo/types/format"

const (
	AddressLength = 20
)

type Address interface {
	format.Byteable
	format.Stringable
	format.ShortStringable
	format.StringTypable
	format.Validatable

	IsZero() bool
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
