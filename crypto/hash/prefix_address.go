package hash

import (
	"fmt"
)

const (
	_ byte = iota
	Sha256AddressPrefixByte
	Sha3AddressPrefixByte
	Keccak256AddressByte
	Blake2b256AddressByte
	PoseidonBN254AddressByte
	MimcBN254AddressByte
	Ripemd160AddressByte
)

var typeToAddressPrefix = map[string]byte{
	Sha256Type:        Sha256AddressPrefixByte,
	Sha3Type:          Sha3AddressPrefixByte,
	Keccak256Type:     Keccak256AddressByte,
	Blake2b256Type:    Blake2b256AddressByte,
	PoseidonBN254Type: PoseidonBN254AddressByte,
	MimcBN254Type:     MimcBN254AddressByte,
	Ripemd160Type:     Ripemd160AddressByte,
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
