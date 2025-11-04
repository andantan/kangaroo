package kangarootransaction

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/transaction"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegistryTransactionSuite(&KangarooTransactionSuite{})
}

type KangarooTransactionSuite struct{}

var _ transaction.TransactionSuite = (*KangarooTransactionSuite)(nil)

func (s *KangarooTransactionSuite) Type() string {
	return transaction.KangarooTransactionType
}

func (s *KangarooTransactionSuite) TransactionFromBytes(data []byte) (transaction.Transaction, error) {
	tx := new(KangarooTransaction)
	if err := codec.DecodeProto(data, tx); err != nil {
		return nil, err
	}
	return tx, nil
}
