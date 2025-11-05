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
