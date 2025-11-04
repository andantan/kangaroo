package core

import (
	"encoding/hex"
	"fmt"
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/transaction"
	"github.com/andantan/kangaroo/registry"
	"strings"
)

func WrapTransaction(tx transaction.Transaction) ([]byte, error) {
	prefix, err := transaction.GetTransactionPrefixFromType(tx.Type())
	if err != nil {
		return nil, fmt.Errorf("configuration error for transaction<%s>: %w", tx.Type(), err)
	}

	txData, err := codec.EncodeProto(tx)
	if err != nil {
		return nil, err
	}

	return append([]byte{prefix}, txData...), nil
}

func WrapTransactionToString(tx transaction.Transaction) (string, error) {
	wrappedBytes, err := WrapTransaction(tx)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(wrappedBytes), nil
}

func UnwrapTransaction(data []byte) (transaction.Transaction, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("transaction data is too short to contain a type prefix")
	}

	typePrefix := data[0]
	keyData := data[1:]

	typeName, err := transaction.GetTypeFromTransactionPrefix(typePrefix)
	if err != nil {
		return nil, err
	}

	suite, err := registry.GetTransactionSuite(typeName)
	if err != nil {
		return nil, err
	}

	return suite.TransactionFromBytes(keyData)
}

func UnwrapTransactionFromString(s string) (transaction.Transaction, error) {
	s = strings.TrimPrefix(s, "0x")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hex string: %w", err)
	}

	return UnwrapTransaction(data)
}
