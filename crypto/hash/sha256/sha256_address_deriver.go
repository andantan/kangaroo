package sha256

import (
	"crypto/sha256"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
)

type Sha256AddressDeriver struct{}

var _ kangaroohash.AddressDeriver = (*Sha256AddressDeriver)(nil)

func (_ *Sha256AddressDeriver) Type() string {
	return kangaroohash.Sha256Type
}

func (_ *Sha256AddressDeriver) Derive(data []byte) kangaroohash.Address {
	hashBytes := sha256.Sum256(data)
	start := len(hashBytes) - kangaroohash.AddressLength
	addrBytes := hashBytes[start:]
	address, err := Sha256AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}

	return address
}
