package wrapper

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapAddress(a hash.Address) ([]byte, error) {
	prefix, err := hash.GetAddressPrefixFromType(a.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for address<%s>: %w", a.Type(), err)
	}
	return append([]byte{prefix}, a.Bytes()...), nil
}

func WrapAddressToString(a hash.Address) (string, error) {
	wrappedBytes, err := WrapAddress(a)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapAddress(data []byte) (hash.Address, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("hash data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	addressData := data[1:]

	typeName, err := hash.GetTypeFromAddressPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetAddressSuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.AddressFromBytes(addressData)
}

func UnwrapAddressFromString(s string) (hash.Address, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address hex string: %w", err)
	}

	return UnwrapAddress(data)
}
