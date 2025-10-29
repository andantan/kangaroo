package keccak256

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/sha3"
)

type Keccak256AddressDeriver struct{}

var _ hash.AddressDeriver = (*Keccak256AddressDeriver)(nil)

func NewKeccak256AddressDeriver() *Keccak256AddressDeriver {
	return &Keccak256AddressDeriver{}
}

func (d *Keccak256AddressDeriver) Derive(data []byte) hash.Addressable {
	kh := sha3.NewLegacyKeccak256()
	kh.Write(data)
	khb := kh.Sum(nil)
	start := len(khb) - hash.AddressLength
	addrBytes := khb[start:]
	address, err := Keccak256AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}
	return address
}
