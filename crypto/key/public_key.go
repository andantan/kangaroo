package key

import (
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
)

type PublicKey interface {
	Bytes() []byte
	String() string
	IsValid() bool
	Type() string

	Equal(other PublicKey) bool
	Address(deriver kangaroohash.AddressDeriver) kangaroohash.Address
}
