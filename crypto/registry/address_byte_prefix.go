package registry

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
)

const (
	_ byte = iota
	SHA256AddressPrefixByte
	KECCAK256AddressByte
	RIPEMD160AddressByte
)

var typeToAddressPrefix = map[string]byte{
	kangaroohash.Sha256Type:    SHA256AddressPrefixByte,
	kangaroohash.Keccak256Type: KECCAK256AddressByte,
	kangaroohash.Ripemd160Type: RIPEMD160AddressByte,
}

var addressPrefixToType = make(map[byte]string)

func init() {
	for name, prefix := range typeToAddressPrefix {
		if _, exists := addressPrefixToType[prefix]; exists {
			panic(fmt.Sprintf("duplicate address type prefix defined: 0x%x", prefix))
		}
		addressPrefixToType[prefix] = name
	}
}

func GetAddressPrefixFromType(name string) (byte, error) {
	prefix, ok := typeToAddressPrefix[name]
	if !ok {
		return 0, fmt.Errorf("no prefix defined for address type: %s", name)
	}
	return prefix, nil
}

func GetTypeFromAddressPrefix(prefix byte) (string, error) {
	name, ok := addressPrefixToType[prefix]
	if !ok {
		return "", fmt.Errorf("unknown address type prefix: 0x%x", prefix)
	}
	return name, nil
}
