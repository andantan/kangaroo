package transaction

import (
	"fmt"
)

const (
	_ byte = iota
	KangarooTransactionPrefixByte
)

var typeToTransactionPrefix = map[string]byte{
	KangarooTransactionType: KangarooTransactionPrefixByte,
}
var transactionPrefixToType = make(map[byte]string)

func init() {
	for name, prefix := range typeToTransactionPrefix {
		if _, exists := transactionPrefixToType[prefix]; exists {
			panic(fmt.Sprintf("duplicate transaction type prefix defined: 0x%x", prefix))
		}
		transactionPrefixToType[prefix] = name
	}
}

func GetTransactionPrefixFromType(name string) (byte, error) {
	prefix, ok := typeToTransactionPrefix[name]
	if !ok {
		return 0, fmt.Errorf("no prefix defined for transaction type: %s", name)
	}
	return prefix, nil
}

func GetTypeFromTransactionPrefix(prefix byte) (string, error) {
	name, ok := transactionPrefixToType[prefix]
	if !ok {
		return "", fmt.Errorf("unknown transaction type prefix: 0x%x", prefix)
	}
	return name, nil
}
