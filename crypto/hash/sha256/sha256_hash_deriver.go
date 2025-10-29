package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha256HashDeriver struct{}

var _ hash.HashDeriver = (*Sha256HashDeriver)(nil)

func NewSha256HashDeriver() *Sha256HashDeriver {
	return &Sha256HashDeriver{}
}

func (_ *Sha256HashDeriver) Derive(data []byte) hash.Hashable {
	hashBytes := sha256.Sum256(data)
	h, err := Sha256HashFromBytes(hashBytes[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid sha256 sum: %v", err))
	}
	return h
}
