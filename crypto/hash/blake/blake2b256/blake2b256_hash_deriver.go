package blake2b256

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/blake2b"
)

type Blake2b256HashDeriver struct{}

var _ hash.HashDeriver = (*Blake2b256HashDeriver)(nil)

func (_ *Blake2b256HashDeriver) Type() string {
	return hash.Blake2b256Type
}

func (_ *Blake2b256HashDeriver) Derive(data []byte) hash.Hash {
	if data == nil {
		return &Blake2b256Hash{}
	}

	hashBytes := blake2b.Sum256(data)
	h, err := Blake2b256HashFromBytes(hashBytes[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid blake2b256 sum: %v", err))
	}
	return h
}
