package ripemd160

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
	"golang.org/x/crypto/ripemd160"
)

func init() {
	kangarooregistry.RegisterAddressDeriver(&Ripemd160AddressDeriver{})
}

type Ripemd160AddressDeriver struct{}

var _ kangaroohash.AddressDeriver = (*Ripemd160AddressDeriver)(nil)

func (_ *Ripemd160AddressDeriver) Type() string {
	return kangaroohash.Ripemd160Type
}

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
