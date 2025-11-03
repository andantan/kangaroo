package registry

import (
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"strings"
)

func ParseHashFromBytes(data []byte) (kangaroohash.Hash, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("hash data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	hashData := data[1:]

	typeName, err := GetTypeFromHashPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := GetHashSuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.HashFromBytes(hashData)
}

func ParseHashFromString(s string) (kangaroohash.Hash, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex string: %w", err)
	}

	return ParseHashFromBytes(data)
}
