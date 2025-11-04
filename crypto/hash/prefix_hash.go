package hash

import (
	"fmt"
)

const (
	_ byte = iota
	Sha256HashPrefixByte
	Keccak256HashByte
	Blake2b256HashByte
)

var typeToHashPrefix = map[string]byte{
	Sha256Type:     Sha256HashPrefixByte,
	Keccak256Type:  Keccak256HashByte,
	Blake2b256Type: Blake2b256HashByte,
}

var hashPrefixToType = make(map[byte]string)

func init() {
	for name, prefix := range typeToHashPrefix {
		if _, exists := hashPrefixToType[prefix]; exists {
			panic(fmt.Sprintf("duplicate hash type prefix defined: 0x%x", prefix))
		}
		hashPrefixToType[prefix] = name
	}
}

func GetHashPrefixFromType(name string) (byte, error) {
	prefix, ok := typeToHashPrefix[name]
	if !ok {
		return 0, fmt.Errorf("no prefix defined for hash type: %s", name)
	}
	return prefix, nil
}

func GetTypeFromHashPrefix(prefix byte) (string, error) {
	name, ok := hashPrefixToType[prefix]
	if !ok {
		return "", fmt.Errorf("unknown hash type prefix: 0x%x", prefix)
	}
	return name, nil
}
