package ecdsa

const (
	ECDSAPrivateKeyBytesLength = 32
	ECDSAPrivateKeyHexLength   = ECDSAPrivateKeyBytesLength * 2
	ECDSAPublicKeyBytesLength  = 33
	ECDSAPublicKeyHexLength    = ECDSAPublicKeyBytesLength * 2
	ECDSASignatureBytesLength  = 64
	ECDSASignatureHexLength    = ECDSASignatureBytesLength * 2
)

const (
	ECDSASecp256k1Type = "ecdsa-secp256k1"
	ECDSASecp256r1Type = "ecdsa-secp256r1"
)
