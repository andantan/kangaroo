package keccak256

import (
	"fmt"
	kangaroocrypto "github.com/andantan/kangaroo/crypto"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/sha3"
)

func init() {
	kangaroocrypto.RegisterAddressDeriver(kangaroohash.Keccak256Type, &Keccak256AddressDeriver{})
}

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
