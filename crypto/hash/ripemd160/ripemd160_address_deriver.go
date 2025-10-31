package ripemd160

import (
	"fmt"
	kangaroocrypto "github.com/andantan/kangaroo/crypto"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/ripemd160"
)

func init() {
	kangaroocrypto.RegisterAddressDeriver(kangaroohash.Ripemd160Type, &Ripemd160AddressDeriver{})
}

type Ripemd160AddressDeriver struct{}

var _ kangaroohash.AddressDeriver = (*Ripemd160AddressDeriver)(nil)
var DefaultRipemd160AddressDeriver = &Ripemd160AddressDeriver{}

func (_ *Ripemd160AddressDeriver) Derive(data []byte) kangaroohash.Address {
	rh := ripemd160.New()
	rh.Write(data)
	rhb := rh.Sum(nil)
	address, err := Ripemd160AddressFromBytes(rhb)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}
	return address
}
