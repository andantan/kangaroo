package keccak256

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"golang.org/x/crypto/sha3"
)

type Keccak256HashDeriver struct{}

var _ hash.HashDeriver = (*Keccak256HashDeriver)(nil)

func (_ *Keccak256HashDeriver) Type() string {
	return hash.Keccak256Type
}

func (_ *Keccak256HashDeriver) Derive(data []byte) hash.Hash {
	kh := sha3.NewLegacyKeccak256()
	kh.Write(data)
	khb := kh.Sum(nil)
	h, err := Keccak256HashFromBytes(khb)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid keccak256 sum: %v", err))
	}
	return h
}
