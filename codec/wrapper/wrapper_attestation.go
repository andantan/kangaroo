package wrapper

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapAttestation(a block.Attestation) ([]byte, error) {
	prefix, err := block.GetAttestationPrefixFromType(a.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for attestation<%s>: %w", a.Type(), err)
	}

	aData, err := codec.EncodeProto(a)
	if err != nil {
		return nil, err
	}

	return append([]byte{prefix}, aData...), nil
}

func WrapAttestationToString(a block.Attestation) (string, error) {
	wrappedAttestation, err := WrapAttestation(a)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedAttestation), nil
}

func UnwrapAttestation(data []byte) (block.Attestation, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("attestation data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	aData := data[1:]

	typeName, err := block.GetTypeFromAttestationPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetAttestationSuite(typeName)
	if err != nil {
		return nil, err
	}

	tx := suite.NewAttestation()
	if err = codec.DecodeProto(aData, tx); err != nil {
		return nil, err
	}

	return tx, nil
}

func UnwrapAttestationFromString(s string) (block.Attestation, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation hex string: %w", err)
	}

	return UnwrapAttestation(data)
}
