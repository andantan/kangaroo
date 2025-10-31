package sha256

import (
	"crypto/sha256"
	"fmt"
	kangaroocrypto "github.com/andantan/kangaroo/crypto"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
)

func init() {
	kangaroocrypto.RegisterHashDeriver(kangaroohash.Sha256Type, &Sha256HashDeriver{})
}

type Sha256HashDeriver struct{}

var _ kangaroohash.HashDeriver = (*Sha256HashDeriver)(nil)
var DefaultSha256HashDeriver = &Sha256HashDeriver{}

func (_ *Sha256HashDeriver) Derive(data []byte) kangaroohash.Hash {
	hashBytes := sha256.Sum256(data)
	h, err := Sha256HashFromBytes(hashBytes[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid sha256 sum: %v", err))
	}
	return h
}
