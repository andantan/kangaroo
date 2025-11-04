package transaction

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"math/big"
)

const (
	KangarooTransactionType = "kangaroo"
)

type Transaction interface {
	hash.Hashable
	key.Signable
	codec.ProtoCodec

	Sign(privKey key.PrivateKey, deriver hash.HashDeriver) error
	Verify(deriver hash.HashDeriver) error
	Type() string

	GetValue() *big.Int
	GetData() []byte
	GetNonce() uint64
	GetSigner() key.PublicKey
}

type TransactionSuite interface {
	Type() string
	TransactionFromBytes(data []byte) (Transaction, error)
}
