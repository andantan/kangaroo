package registry

import (
	"fmt"
	kangarooecdsa "github.com/andantan/kangaroo/crypto/key/ecdsa"
	kangarooeddsa "github.com/andantan/kangaroo/crypto/key/eddsa"
)

const (
	_ byte = iota
	ECDSASecp256r1PrefixByte
	ECDSASecp256k1PrefixByte
	EdDSAEd25519PrefixByte
)

// mapping algorithm type name to 1 byte prefix
var typeToKeyPrefix = map[string]byte{
	kangarooecdsa.ECDSASecp256r1Type: ECDSASecp256r1PrefixByte,
	kangarooecdsa.ECDSASecp256k1Type: ECDSASecp256k1PrefixByte,
	kangarooeddsa.EdDSAEd25519Type:   EdDSAEd25519PrefixByte,
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
