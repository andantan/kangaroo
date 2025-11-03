package registry

import (
	"encoding/hex"
	"fmt"
	kangarookey "github.com/andantan/kangaroo/crypto/key"
	"strings"
)

func ParsePrivateKeyFromBytes(data []byte) (kangarookey.PrivateKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("private key data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	keyData := data[1:]

	typeName, err := GetTypeFromKeyPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := GetKeySuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.PrivateKeyFromBytes(keyData)
}

func ParsePrivateKeyFromString(s string) (kangarookey.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid private-key hex string: %w", err)
	}

	return ParsePrivateKeyFromBytes(data)
}

func ParsePublicKeyFromBytes(data []byte) (kangarookey.PublicKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("public key data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	keyData := data[1:]

	typeName, err := GetTypeFromKeyPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := GetKeySuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.PublicKeyFromBytes(keyData)
}

func ParsePublicKeyFromString(s string) (kangarookey.PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid public-key hex string: %w", err)
	}

	return ParsePublicKeyFromBytes(data)
}

func ParseSignatureFromBytes(data []byte) (kangarookey.Signature, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("signature data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	sigData := data[1:]

	typeName, err := GetTypeFromKeyPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := GetKeySuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.SignatureFromBytes(sigData)
}

func ParseSignatureFromString(s string) (kangarookey.Signature, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex string: %w", err)
	}

	return ParseSignatureFromBytes(data)
}
