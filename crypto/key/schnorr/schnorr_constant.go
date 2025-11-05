package schnorr

const (
	SchnorrSecp256k1Type                  = "schnorr-secp256k1"
	SchnorrSecp256k1PrivateKeyBytesLength = 32
	SchnorrSecp256k1PublicKeyBytesLength  = 33
	SchnorrSecp256k1SignatureBytesLength  = 64
	SchnorrSecp256k1PrivateKeyHexLength   = SchnorrSecp256k1PrivateKeyBytesLength * 2
	SchnorrSecp256k1PublicKeyHexLength    = SchnorrSecp256k1PublicKeyBytesLength * 2
	SchnorrSecp256k1SignatureHexLength    = SchnorrSecp256k1SignatureBytesLength * 2
)

const (
	SchnorrSr25519Type                  = "schnorr-sr25519"
	SchnorrSr25519ContextString         = "kangaroo-schnorr-sr25519-context-string"
	SchnorrSr25519PrivateKeyBytesLength = 32
	SchnorrSr25519PublicKeyBytesLength  = 32
	SchnorrSr25519SignatureBytesLength  = 64
	SchnorrSr25519PrivateKeyHexLength   = SchnorrSr25519PrivateKeyBytesLength * 2
	SchnorrSr25519PublicKeyHexLength    = SchnorrSr25519PublicKeyBytesLength * 2
	SchnorrSr25519SignatureHexLength    = SchnorrSr25519SignatureBytesLength * 2
)
