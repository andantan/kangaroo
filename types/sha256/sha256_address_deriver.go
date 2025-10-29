package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/andantan/kangaroo/types"
)

type SHA256AddressDeriver struct{}

var _ types.AddressDeriver = (*SHA256AddressDeriver)(nil)

func NewSHA256AddressDeriver() *SHA256AddressDeriver {
	return &SHA256AddressDeriver{}
}

func (d *SHA256AddressDeriver) Derive(data []byte) types.Addressable {
	hashBytes := sha256.Sum256(data)
	start := len(hashBytes) - types.AddressLength
	addrBytes := hashBytes[start:]
	address, err := SHA256AddressFromBytes(addrBytes)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to derive address from valid hash slice: %v", err))
	}

	return address
}
