package key

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/key/ecdsa"
	"github.com/andantan/kangaroo/crypto/key/eddsa"
	"github.com/andantan/kangaroo/crypto/key/schnorr"
)

const (
	_ byte = iota
	ECDSASecp256r1PrefixByte
	ECDSASecp256k1PrefixByte
	EdDSAEd25519PrefixByte
	EdDSAEd448PrefixByte
	SchnorrSecp256k1PrefixByte
)

// mapping algorithm type name to 1 byte prefix
var typeToKeyPrefix = map[string]byte{
	ecdsa.ECDSASecp256r1Type:     ECDSASecp256r1PrefixByte,
	ecdsa.ECDSASecp256k1Type:     ECDSASecp256k1PrefixByte,
	eddsa.EdDSAEd25519Type:       EdDSAEd25519PrefixByte,
	eddsa.EdDSAEd448Type:         EdDSAEd448PrefixByte,
	schnorr.SchnorrSecp256k1Type: SchnorrSecp256k1PrefixByte,
}

var keyPrefixToType = make(map[byte]string)

func init() {
	for name, prefix := range typeToKeyPrefix {
		if _, exists := keyPrefixToType[prefix]; exists {
			panic(fmt.Sprintf("duplicate key type prefix defined: 0x%x", prefix))
		}
		keyPrefixToType[prefix] = name
	}
}

func GetKeyPrefixFromType(name string) (byte, error) {
	prefix, ok := typeToKeyPrefix[name]
	if !ok {
		return 0, fmt.Errorf("no prefix defined for key type: %s", name)
	}
	return prefix, nil
}

func GetTypeFromKeyPrefix(prefix byte) (string, error) {
	name, ok := keyPrefixToType[prefix]
	if !ok {
		return "", fmt.Errorf("unknown key type prefix: 0x%x", prefix)
	}
	return name, nil
}
