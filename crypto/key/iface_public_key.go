package key

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/types/format"
)

type PublicKey interface {
	format.Byteable
	format.Stringable
	format.StringTypable
	format.Validatable

	Equal(other PublicKey) bool
	Address(deriver hash.AddressDeriver) hash.Address
}
