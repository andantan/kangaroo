package key

type Signature interface {
	Bytes() []byte
	String() string
	IsValid() bool
	Type() string

	Equal(other Signature) bool
	Verify(pubKey PublicKey, data []byte) bool
}
