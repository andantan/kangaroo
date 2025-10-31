package key

type KeySuite interface {
	Type() string
	GeneratePrivateKey() (PrivateKey, error)
	PrivateKeyFromBytes(data []byte) (PrivateKey, error)
	PublicKeyFromBytes(data []byte) (PublicKey, error)
	SignatureFromBytes(data []byte) (Signature, error)
}
