package crypto

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapHash(h hash.Hash) ([]byte, error) {
	prefix, err := hash.GetHashPrefixFromType(h.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for hash<%s>: %w", h.Type(), err)
	}
	return append([]byte{prefix}, h.Bytes()...), nil
}

func WrapHashToString(a hash.Hash) (string, error) {
	wrappedBytes, err := WrapHash(a)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapHash(data []byte) (hash.Hash, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("hash data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	hashData := data[1:]

	typeName, err := hash.GetTypeFromHashPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetHashSuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.HashFromBytes(hashData)
}

func UnwrapHashFromString(s string) (hash.Hash, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex string: %w", err)
	}

	return UnwrapHash(data)
}
