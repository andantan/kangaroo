package wrapper

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapSignature(s key.Signature) ([]byte, error) {
	prefix, err := key.GetKeyPrefixFromType(s.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for signature<%s>: %w", s.Type(), err)
	}
	return append([]byte{prefix}, s.Bytes()...), nil
}

func WrapSignatureToString(k key.Signature) (string, error) {
	wrappedBytes, err := WrapSignature(k)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapSignature(data []byte) (key.Signature, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("signature data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	sigData := data[1:]

	typeName, err := key.GetTypeFromKeyPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetKeySuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.SignatureFromBytes(sigData)
}

func UnwrapSignatureFromString(s string) (key.Signature, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex string: %w", err)
	}

	return UnwrapSignature(data)
}
