package wrapper

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapPrivateKey(k key.PrivateKey) ([]byte, error) {
	prefix, err := key.GetKeyPrefixFromType(k.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for private-key<%s>: %w", k.Type(), err)
	}
	return append([]byte{prefix}, k.Bytes()...), nil
}

func WrapPrivateKeyToString(k key.PrivateKey) (string, error) {
	wrappedBytes, err := WrapPrivateKey(k)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapPrivateKey(data []byte) (key.PrivateKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("private key data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	keyData := data[1:]

	typeName, err := key.GetTypeFromKeyPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetKeySuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.PrivateKeyFromBytes(keyData)
}

func UnwrapPrivateKeyFromString(s string) (key.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid private-key hex string: %w", err)
	}

	return UnwrapPrivateKey(data)
}
