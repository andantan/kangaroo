package wrapper

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapPublicKey(k key.PublicKey) ([]byte, error) {
	prefix, err := key.GetKeyPrefixFromType(k.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for public-key<%s>: %w", k.Type(), err)
	}
	return append([]byte{prefix}, k.Bytes()...), nil
}

func WrapPublicKeyToString(k key.PublicKey) (string, error) {
	wrappedBytes, err := WrapPublicKey(k)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapPublicKey(data []byte) (key.PublicKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("public key data is too short to contain a type prefix")
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

	return suite.PublicKeyFromBytes(keyData)
}

func UnwrapPublicKeyFromString(s string) (key.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid public-key hex string: %w", err)
	}

	return UnwrapPublicKey(data)
}
