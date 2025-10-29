package crypto

import "github.com/andantan/kangaroo/types"

type PublicKey interface {
	Bytes() []byte
	String() string
	IsValid() bool
	Type() string

	Equal(other PublicKey) bool
	Address(deriver types.AddressDeriver) types.Addressable
}
