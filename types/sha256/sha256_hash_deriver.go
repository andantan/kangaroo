package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/andantan/kangaroo/types"
)

type SHA256HashDeriver struct{}

var _ types.HashDeriver = (*SHA256HashDeriver)(nil)

func NewSHA256HashDeriver() *SHA256HashDeriver {
	return &SHA256HashDeriver{}
}

func (s *SHA256HashDeriver) Derive(data []byte) types.Hashable {
	hashBytes := sha256.Sum256(data)
	h, err := SHA256HashFromBytes(hashBytes[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid sha256 sum: %v", err))
	}
	return h
}
