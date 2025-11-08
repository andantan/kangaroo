package block

import "fmt"

const (
	_ byte = iota
	KangarooAttestationPrefixByte
)

var typeToAttestationPrefix = map[string]byte{
	KangarooAttestationType: KangarooAttestationPrefixByte,
}
var attestationPrefixToType = make(map[byte]string)

func init() {
	for name, prefix := range typeToAttestationPrefix {
		if _, exists := attestationPrefixToType[prefix]; exists {
			panic(fmt.Sprintf("duplicate attestation type prefix defined: 0x%x", prefix))
		}
		attestationPrefixToType[prefix] = name
	}
}

func GetAttestationPrefixFromType(name string) (byte, error) {
	prefix, ok := typeToAttestationPrefix[name]
	if !ok {
		return 0, fmt.Errorf("no prefix defined for attestation type: %s", name)
	}
	return prefix, nil
}

func GetTypeFromAttestationPrefix(prefix byte) (string, error) {
	name, ok := attestationPrefixToType[prefix]
	if !ok {
		return "", fmt.Errorf("unknown attestation type prefix: 0x%x", prefix)
	}
	return name, nil
}
