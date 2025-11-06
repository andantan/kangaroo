package transaction

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/types/format"
	"math/big"
)

const (
	KangarooTransactionType = "kangaroo"
)

type Transaction interface {
	hash.Hashable        // txid
	key.Signable         // digest
	key.EmbeddedSigner   // sign, verify
	codec.ProtoCodec     // protobuf
	format.Stringable    // string format
	format.StringTypable // string type

	GetValue() *big.Int
	GetData() []byte
	GetNonce() uint64
	GetSigner() key.PublicKey
}

type TransactionSuite interface {
	format.StringTypable

	NewTransaction() Transaction
}
