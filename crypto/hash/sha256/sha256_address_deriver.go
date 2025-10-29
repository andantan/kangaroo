package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha256AddressDeriver struct{}

var _ hash.AddressDeriver = (*Sha256AddressDeriver)(nil)

func NewSha256AddressDeriver() *Sha256AddressDeriver {
	return &Sha256AddressDeriver{}
}

func (d *Sha256AddressDeriver) Derive(data []byte) hash.Addressable {
	hashBytes := sha256.Sum256(data)
	start := len(hashBytes) - hash.AddressLength
	addrBytes := hashBytes[start:]
	address, err := Sha256AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}

	return address
}
