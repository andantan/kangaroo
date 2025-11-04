package key

import "github.com/andantan/kangaroo/types/format"

type KeySuite interface {
	format.StringTypable

	GeneratePrivateKey() (PrivateKey, error)
	PrivateKeyFromBytes(data []byte) (PrivateKey, error)
	PublicKeyFromBytes(data []byte) (PublicKey, error)
	SignatureFromBytes(data []byte) (Signature, error)
}
