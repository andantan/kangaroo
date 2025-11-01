package sha256

import (
	"crypto/sha256"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	kangarooregistry "github.com/andantan/kangaroo/crypto/registry"
)

func init() {
	kangarooregistry.RegisterHashDeriver(&Sha256HashDeriver{})
}

type Sha256HashDeriver struct{}

var _ kangaroohash.HashDeriver = (*Sha256HashDeriver)(nil)

func (_ *Sha256HashDeriver) Type() string {
	return kangaroohash.Sha256Type
}

func (_ *Sha256HashDeriver) Derive(data []byte) kangaroohash.Hash {
	hashBytes := sha256.Sum256(data)
	h, err := Sha256HashFromBytes(hashBytes[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid sha256 sum: %v", err))
	}
	return h
}
