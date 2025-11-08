package key

import "github.com/andantan/kangaroo/types/format"

type PrivateKey interface {
	format.Byteable
	format.Stringable
	format.ShortStringable
	format.StringTypable
	format.Validatable

	PublicKey() PublicKey
	Sign(data []byte) (Signature, error)
}
