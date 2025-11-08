package kangaroobody

import (
	"errors"
	"fmt"
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/core/transaction"
	"github.com/andantan/kangaroo/crypto/hash"
	kangarooblockpb "github.com/andantan/kangaroo/proto/core/block/pb"
	"google.golang.org/protobuf/proto"
	"sort"
	"strings"
)

type KangarooBody struct {
	Transactions []transaction.Transaction
}

var _ block.Body = (*KangarooBody)(nil)

func NewKangarooBody(txs []transaction.Transaction) *KangarooBody {
	if txs == nil {
		txs = make([]transaction.Transaction, 0)
	}
	return &KangarooBody{
		Transactions: txs,
	}
}

func (b *KangarooBody) Hash(deriver hash.HashDeriver) (hash.Hash, error) {
	if b.Transactions == nil {
		return nil, errors.New("transactions is nil")
	}

	if len(b.Transactions) == 0 {
		return deriver.Derive(nil), nil
	}

	txHashes := make([]hash.Hash, len(b.Transactions))
	for i, tx := range b.Transactions {
		h, err := tx.Hash(deriver)
		if err != nil {
			return nil, fmt.Errorf("failed to get hash for tx %d: %w", i, err)
		}
		txHashes[i] = h
	}

	sort.Slice(txHashes, func(i, j int) bool {
		return txHashes[i].Lt(txHashes[j])
	})

	for len(txHashes) > 1 {
		if len(txHashes)%2 != 0 {
			txHashes = append(txHashes, txHashes[len(txHashes)-1])
		}

		var nextLevelHashes []hash.Hash
		for i := 0; i < len(txHashes); i += 2 {
			left := txHashes[i]
			right := txHashes[i+1]
			combinedHashData := append(left.Bytes(), right.Bytes()...)
			parentHash := deriver.Derive(combinedHashData)
			nextLevelHashes = append(nextLevelHashes, parentHash)
		}
		txHashes = nextLevelHashes
	}

	return txHashes[0], nil
}

func (b *KangarooBody) ToProto() (proto.Message, error) {
	txxBytes := make([][]byte, len(b.Transactions))

	for i, tx := range b.Transactions {
		wrappedTxBytes, err := wrapper.WrapTransaction(tx)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap transaction %d: %w", i, err)
		}
		txxBytes[i] = wrappedTxBytes
	}

	return &kangarooblockpb.KangarooBody{
		Transactions: txxBytes,
	}, nil
}

func (b *KangarooBody) FromProto(m proto.Message) error {
	pb, ok := m.(*kangarooblockpb.KangarooBody)
	if !ok {
		return fmt.Errorf("cannot deserialize protobuf Kangaroobody")
	}

	txx := make([]transaction.Transaction, len(pb.Transactions))
	for i, wrappedTxBytes := range pb.Transactions {
		unwrappedTx, err := wrapper.UnwrapTransaction(wrappedTxBytes)
		if err != nil {
			return fmt.Errorf("failed to unwrap transaction %d: %w", i, err)
		}
		txx[i] = unwrappedTx
	}

	b.Transactions = txx
	return nil
}

func (b *KangarooBody) NewProto() proto.Message {
	return &kangarooblockpb.KangarooBody{}
}

func (b *KangarooBody) String() string {
	txCount := b.GetWeight()
	txTypes := make([]string, 0, 3)
	for i, tx := range b.Transactions {
		if i >= 3 {
			txTypes = append(txTypes, "...")
			break
		}
		txTypes = append(txTypes, tx.Type())
	}

	return fmt.Sprintf("Body<%s>{Weight: %d, Transactions: [%s]}",
		b.Type(), txCount, strings.Join(txTypes, ", "))
}

func (b *KangarooBody) Type() string {
	return block.KangarooBodyType
}

func (b *KangarooBody) GetTransactions() []transaction.Transaction {
	return b.Transactions
}

func (b *KangarooBody) GetWeight() uint64 {
	return uint64(len(b.Transactions))
}
