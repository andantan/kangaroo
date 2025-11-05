package ecdsa

const (
	ECDSASecp256r1Type                  = "ecdsa-secp256r1"
	ECDSASecp256r1PrivateKeyBytesLength = 32
	ECDSASecp256r1PublicKeyBytesLength  = 33
	ECDSASecp256r1SignatureBytesLength  = 64
	ECDSASecp256r1PrivateKeyHexLength   = ECDSASecp256r1PrivateKeyBytesLength * 2
	ECDSASecp256r1PublicKeyHexLength    = ECDSASecp256r1PublicKeyBytesLength * 2
	ECDSASecp256r1SignatureHexLength    = ECDSASecp256r1SignatureBytesLength * 2
)

const (
	ECDSASecp256k1Type                  = "ecdsa-secp256k1"
	ECDSASecp256k1PrivateKeyBytesLength = 32
	ECDSASecp256k1PublicKeyBytesLength  = 33
	ECDSASecp256k1SignatureBytesLength  = 64
	ECDSASecp256k1PrivateKeyHexLength   = ECDSASecp256k1PrivateKeyBytesLength * 2
	ECDSASecp256k1PublicKeyHexLength    = ECDSASecp256k1PublicKeyBytesLength * 2
	ECDSASecp256k1SignatureHexLength    = ECDSASecp256k1SignatureBytesLength * 2
)
