package eddsa

import "crypto/ed25519"

const (
	EdDSAPrivateKeyBytesLength = ed25519.PrivateKeySize
	EdDSAPublicKeyBytesLength  = ed25519.PublicKeySize
	EdDSASignatureBytesLength  = ed25519.SignatureSize
)

const (
	EdDSAEd25519Type = "eddsa-ed25519"
)
