package keccak256

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/sha3"
)

type Keccak256AddressDeriver struct{}

var _ hash.AddressDeriver = (*Keccak256AddressDeriver)(nil)

func (_ *Keccak256AddressDeriver) Type() string {
	return hash.Keccak256Type
}

func (_ *Keccak256AddressDeriver) Derive(data []byte) hash.Address {
	if data == nil {
		return &Keccak256Address{}
	}

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
