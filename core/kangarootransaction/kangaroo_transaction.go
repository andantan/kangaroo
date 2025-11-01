package kangarootransaction

import (
	kangarookey "github.com/andantan/kangaroo/crypto/key"
)

const (
	KangarooTransactionType = "kangaroo-transaction"
)

type KangarooTransaction struct {
	Data      []byte
	Nonce     uint64
	Signature kangarookey.Signature
	Signer    kangarookey.PublicKey
}
