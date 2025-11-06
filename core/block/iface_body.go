package block

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/core/transaction"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/types/format"
)

const (
	KangarooBodyType = "kangaroo"
)

type Body interface {
	hash.Hashable
	codec.ProtoCodec
	format.Stringable
	format.StringTypable

	GetTransactions() []transaction.Transaction
	GetWeight() uint64
}

type BodySuite interface {
	format.StringTypable

	NewBody() Body
}
