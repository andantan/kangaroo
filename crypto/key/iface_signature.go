package key

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/types/format"
)

type Signature interface {
	format.Byteable
	format.Stringable
	format.ShortStringable
	format.StringTypable
	format.Validatable

	Equal(other Signature) bool
	Verify(pubKey PublicKey, data []byte) bool
}

type Signable interface {
	HashForSigning(deriver hash.HashDeriver) (hash.Hash, error)
}

type Signer interface {
	Sign(privKey PrivateKey, item Signable, deriver hash.HashDeriver) (Signature, error)
	Verify(pubKey PublicKey, sig Signature, deriver hash.HashDeriver) error
}

type EmbeddedSigner interface {
	Sign(privKey PrivateKey, deriver hash.HashDeriver) error
	Verify(deriver hash.HashDeriver) error
}
