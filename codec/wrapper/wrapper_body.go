package wrapper

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapBody(b block.Body) ([]byte, error) {
	prefix, err := block.GetBodyPrefixFromType(b.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for body<%s>: %w", b.Type(), err)
	}

	bodyData, err := codec.EncodeProto(b)
	if err != nil {
		return nil, err
	}

	return append([]byte{prefix}, bodyData...), nil
}

func WrapBodyToString(b block.Body) (string, error) {
	wrappedBytes, err := WrapBody(b)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapBody(data []byte) (block.Body, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("body data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	bodyData := data[1:]

	typeName, err := block.GetTypeFromBodyPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetBodySuite(typeName)
	if err != nil {
		return nil, err
	}

	body := suite.NewBody()
	if err = codec.DecodeProto(bodyData, body); err != nil {
		return nil, err
	}

	return body, nil
}

func UnwrapBodyFromString(s string) (block.Body, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid body hex string: %w", err)
	}

	return UnwrapBody(data)
}
