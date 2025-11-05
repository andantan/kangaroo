package sha3

import (
	"crypto/sha3"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha3AddressDeriver struct{}

var _ hash.AddressDeriver = (*Sha3AddressDeriver)(nil)

func (_ *Sha3AddressDeriver) Type() string {
	return hash.Sha3Type
}

func (_ *Sha3AddressDeriver) Derive(data []byte) hash.Address {
	hashBytes := sha3.Sum256(data)
	start := len(hashBytes) - hash.AddressLength
	addrBytes := hashBytes[start:]
	address, err := Sha3AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}
	return address
}
