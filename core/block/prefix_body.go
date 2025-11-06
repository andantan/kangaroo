package block

import "fmt"

const (
	_ byte = iota
	KangarooBodyPrefixByte
)

var typeToBodyPrefix = map[string]byte{
	KangarooBodyType: KangarooBodyPrefixByte,
}
var bodyPrefixToType = make(map[byte]string)

func init() {
	for name, prefix := range typeToBodyPrefix {
		if _, exists := bodyPrefixToType[prefix]; exists {
			panic(fmt.Sprintf("duplicate body type prefix defined: 0x%x", prefix))
		}
		bodyPrefixToType[prefix] = name
	}
}

func GetBodyPrefixFromType(name string) (byte, error) {
	prefix, ok := typeToBodyPrefix[name]
	if !ok {
		return 0, fmt.Errorf("no prefix defined for body type: %s", name)
	}
	return prefix, nil
}

func GetTypeFromBodyPrefix(prefix byte) (string, error) {
	name, ok := bodyPrefixToType[prefix]
	if !ok {
		return "", fmt.Errorf("unknown body type prefix: 0x%x", prefix)
	}
	return name, nil
}
