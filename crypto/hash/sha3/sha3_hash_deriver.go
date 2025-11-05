package sha3

import (
	"crypto/sha3"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
)

type Sha3HashDeriver struct{}

var _ hash.HashDeriver = (*Sha3HashDeriver)(nil)

func (_ *Sha3HashDeriver) Type() string {
	return hash.Sha3Type
}

func (_ *Sha3HashDeriver) Derive(data []byte) hash.Hash {
	hashBytes := sha3.Sum256(data)
	h, err := Sha3HashFromBytes(hashBytes[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid sha3 sum: %v", err))
	}
	return h
}
