package key

import (
	"github.com/andantan/kangaroo/crypto/hash"
)

type Signature interface {
	Bytes() []byte
	String() string
	IsValid() bool
	Type() string

	Equal(other Signature) bool
	Verify(pubKey PublicKey, data []byte) bool
}

type Signable interface {
	HashForSigning(deriver hash.HashDeriver) (hash.Hash, error)
}
