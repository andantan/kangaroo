package eddsa

const (
	EdDSAEd25519Type                  = "eddsa-ed25519"
	EdDSAEd25519PrivateKeyBytesLength = 64
	EdDSAEd25519PublicKeyBytesLength  = 32
	EdDSAEd25519SignatureBytesLength  = 64
	EdDSAEd25519PrivateKeyHexLength   = EdDSAEd25519PrivateKeyBytesLength * 2
	EdDSAEd25519PublicKeyHexLength    = EdDSAEd25519PublicKeyBytesLength * 2
	EdDSAEd25519SignatureHexLength    = EdDSAEd25519SignatureBytesLength * 2
)

const (
	EdDSAEd448Type                  = "eddsa-ed448"
	EdDSAEd448ContextString         = "kangaroo-eddsa-ed448-context-string"
	EdDSAEd448PrivateKeyBytesLength = 114
	EdDSAEd448PublicKeyBytesLength  = 57
	EdDSAEd448SignatureBytesLength  = 114
	EdDSAEd448PrivateKeyHexLength   = EdDSAEd448PrivateKeyBytesLength * 2
	EdDSAEd448PublicKeyHexLength    = EdDSAEd448PublicKeyBytesLength * 2
	EdDSAEd448SignatureHexLength    = EdDSAEd448SignatureBytesLength * 2
)
