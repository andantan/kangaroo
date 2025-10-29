package eddsa

import "crypto/ed25519"

const (
	EdDSAPrivateKeyBytesLength = ed25519.PrivateKeySize
	EdDSAPrivateKeyHexLength   = EdDSAPrivateKeyBytesLength * 2
	EdDSAPublicKeyBytesLength  = ed25519.PublicKeySize
	EdDSAPublicKeyHexLength    = EdDSAPublicKeyBytesLength * 2
	EdDSASignatureBytesLength  = ed25519.SignatureSize
	EdDSASignatureHexLength    = EdDSASignatureBytesLength * 2
)

const (
	EdDSAEd25519Type = "eddsa-ed25519"
)
