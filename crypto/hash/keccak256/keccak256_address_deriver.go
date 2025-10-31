package keccak256

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/sha3"
)

type Keccak256AddressDeriver struct{}

var _ kangaroohash.AddressDeriver = (*Keccak256AddressDeriver)(nil)
var DefaultKeccak256AddressDeriver = &Keccak256AddressDeriver{}

func (_ *Keccak256AddressDeriver) Derive(data []byte) kangaroohash.Address {
	kh := sha3.NewLegacyKeccak256()
	kh.Write(data)
	khb := kh.Sum(nil)
	start := len(khb) - kangaroohash.AddressLength
	addrBytes := khb[start:]
	address, err := Keccak256AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}
	return address
}
