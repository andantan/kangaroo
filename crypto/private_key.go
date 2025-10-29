package crypto

type PrivateKey interface {
	Bytes() []byte
	String() string
	IsValid() bool
	Type() string

	PublicKey() PublicKey
	Sign(data []byte) (Signature, error)
}
