package blake2b256

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/blake2b"
)

type Blake2b256AddressDeriver struct{}

var _ hash.AddressDeriver = (*Blake2b256AddressDeriver)(nil)

func (_ *Blake2b256AddressDeriver) Type() string {
	return hash.Blake2b256Type
}

func (_ *Blake2b256AddressDeriver) Derive(data []byte) hash.Address {
	if data == nil {
		return &Blake2b256Address{}
	}

	hashBytes := blake2b.Sum256(data)
	start := len(hashBytes) - hash.AddressLength
	addrBytes := hashBytes[start:]
	address, err := Blake2b256AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}
	return address
}
