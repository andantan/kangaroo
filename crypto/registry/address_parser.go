package registry

import (
	"encoding/hex"
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"strings"
)

func ParseAddressFromBytes(data []byte) (kangaroohash.Address, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("hash data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	hashData := data[1:]

	typeName, err := GetTypeFromAddressPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := GetAddressSuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.AddressFromBytes(hashData)
}

func ParseAddressFromString(s string) (kangaroohash.Address, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex string: %w", err)
	}

	return ParseAddressFromBytes(data)
}
