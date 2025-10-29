package ripemd160

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/ripemd160"
)

type Ripemd160AddressDeriver struct{}

var _ hash.AddressDeriver = (*Ripemd160AddressDeriver)(nil)

func NewRipemd160AddressDeriver() *Ripemd160AddressDeriver {
	return &Ripemd160AddressDeriver{}
}

func (d *Ripemd160AddressDeriver) Derive(data []byte) hash.Addressable {
	rh := ripemd160.New()
	rh.Write(data)
	rhb := rh.Sum(nil)
	address, err := Ripemd160AddressFromBytes(rhb)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}
	return address
}
