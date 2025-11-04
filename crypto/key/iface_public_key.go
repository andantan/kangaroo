package key

import (
	"github.com/andantan/kangaroo/crypto/hash"
)

type PublicKey interface {
	Bytes() []byte
	String() string
	IsValid() bool
	Type() string

	Equal(other PublicKey) bool
	Address(deriver hash.AddressDeriver) hash.Address
}
