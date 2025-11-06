package kangarootransaction

import (
	"fmt"
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/core/transaction"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/crypto/sign"
	kangarootxpb "github.com/andantan/kangaroo/proto/core/transaction/pb"
	"google.golang.org/protobuf/proto"
	"math/big"
)

type KangarooTransaction struct {
	ToAddress hash.Address
	Value     *big.Int
	Data      []byte
	Nonce     uint64
	Signature key.Signature
	Signer    key.PublicKey
}

var _ transaction.Transaction = (*KangarooTransaction)(nil)

func NewKangarooTransaction(to hash.Address, value *big.Int, data []byte, nonce uint64) *KangarooTransaction {
	val := value
	if val == nil {
		val = big.NewInt(0)
	}

	return &KangarooTransaction{
		ToAddress: to,
		Value:     val,
		Data:      data,
		Nonce:     nonce,
	}
}

func (tx *KangarooTransaction) Hash(deriver hash.HashDeriver) (hash.Hash, error) {
	if tx.Signature == nil || tx.Signer == nil {
		return nil, fmt.Errorf("cannot hash unsigned transaction")
	}

	if !tx.Signer.IsValid() {
		return nil, fmt.Errorf("invalid signer")
	}

	if !tx.Signature.IsValid() {
		return nil, fmt.Errorf("invalid signature")
	}

	b, err := codec.EncodeProto(tx)
	if err != nil {
		return nil, err
	}

	return deriver.Derive(b), nil
}

func (tx *KangarooTransaction) HashForSigning(deriver hash.HashDeriver) (hash.Hash, error) {
	var (
		err     error
		toBytes []byte
	)
	if tx.ToAddress != nil {
		if toBytes, err = wrapper.WrapAddress(tx.ToAddress); err != nil {
			return nil, err
		}
	}

	var valBytes []byte
	if tx.Value != nil {
		valBytes = tx.Value.Bytes()
	}

	dataProto := &kangarootxpb.KangarooTransactionData{
		ToAddress: toBytes,
		Value:     valBytes,
		Data:      tx.Data,
		Nonce:     tx.Nonce,
	}

	b, err := proto.Marshal(dataProto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tx data for signing: %w", err)
	}

	return deriver.Derive(b), nil
}

func (tx *KangarooTransaction) ToProto() (proto.Message, error) {
	var (
		err     error
		toBytes []byte
	)

	if tx.ToAddress != nil {
		if toBytes, err = wrapper.WrapAddress(tx.ToAddress); err != nil {
			return nil, err
		}
	}

	var valBytes []byte
	if tx.Value != nil {
		valBytes = tx.Value.Bytes()
	}

	var sigBytes []byte
	if tx.Signature != nil {
		if sigBytes, err = wrapper.WrapSignature(tx.Signature); err != nil {
			return nil, err
		}
	}

	var signerBytes []byte
	if tx.Signer != nil {
		if signerBytes, err = wrapper.WrapPublicKey(tx.Signer); err != nil {
			return nil, err
		}
	}

	return &kangarootxpb.KangarooTransaction{
		ToAddress: toBytes,
		Value:     valBytes,
		Data:      tx.Data,
		Nonce:     tx.Nonce,
		Signature: sigBytes,
		Signer:    signerBytes,
	}, nil
}

func (tx *KangarooTransaction) FromProto(m proto.Message) error {
	pb, ok := m.(*kangarootxpb.KangarooTransaction)
	if !ok {
		return fmt.Errorf("cannot deserialize protobuf KangarooTransaction")
	}

	if len(pb.ToAddress) > 0 {
		toAddr, err := wrapper.UnwrapAddress(pb.ToAddress)
		if err != nil {
			return err
		}
		tx.ToAddress = toAddr
	}

	if len(pb.Value) > 0 {
		tx.Value = new(big.Int).SetBytes(pb.Value)
	} else {
		tx.Value = big.NewInt(0)
	}

	if len(pb.Signer) > 0 {
		decPubKey, err := wrapper.UnwrapPublicKey(pb.Signer)
		if err != nil {
			return fmt.Errorf("failed to parse transaction public key: %w", err)
		}
		tx.Signer = decPubKey
	}

	if len(pb.Signature) > 0 {
		decSig, err := wrapper.UnwrapSignature(pb.Signature)
		if err != nil {
			return fmt.Errorf("failed to parse transaction signature: %w", err)
		}
		tx.Signature = decSig
	}

	tx.Data = pb.Data
	tx.Nonce = pb.Nonce

	return nil
}

func (tx *KangarooTransaction) NewProto() proto.Message {
	return &kangarootxpb.KangarooTransaction{}
}

func (tx *KangarooTransaction) Sign(privKey key.PrivateKey, deriver hash.HashDeriver) error {
	sig, err := sign.Sign(privKey, tx, deriver)
	if err != nil {
		return err
	}
	tx.Signature = sig
	tx.Signer = privKey.PublicKey()
	return nil
}

func (tx *KangarooTransaction) Verify(deriver hash.HashDeriver) error {
	errPrefix := "failed to verify transaction"
	if tx.Signer == nil || tx.Signature == nil {
		return fmt.Errorf("%s: not signed", errPrefix)
	}

	if !tx.Signer.IsValid() {
		return fmt.Errorf("%s: invalid signer", errPrefix)
	}

	if !tx.Signature.IsValid() {
		return fmt.Errorf("%s: invalid signature", errPrefix)
	}

	h, err := tx.HashForSigning(deriver)
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	err = sign.VerifySignature(tx.Signer, tx.Signature, h)
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	return nil
}

func (tx *KangarooTransaction) String() string {
	toAddr := "<nil>"
	if tx.ToAddress != nil {
		fullAddr := tx.ToAddress.String()
		if len(fullAddr) > 10 {
			toAddr = fullAddr[:10] + "..."
		} else {
			toAddr = fullAddr
		}
	}

	value := "<nil>"
	if tx.Value != nil {
		value = tx.Value.String()
	}

	signerAddr := "<nil>"
	if tx.Signer != nil {
		fullAddr := tx.Signer.String()
		if len(fullAddr) > 10 {
			signerAddr = fullAddr[:10] + "..."
		} else {
			signerAddr = fullAddr
		}
	}

	return fmt.Sprintf("Transaction<%s>{ToAddress: %s, Value: %s, Nonce: %d, DataSize: %d, Signer: %s}",
		tx.Type(), toAddr, value, tx.Nonce, len(tx.Data), signerAddr)
}

func (tx *KangarooTransaction) Type() string {
	return transaction.KangarooTransactionType
}

func (tx *KangarooTransaction) GetData() []byte {
	return append([]byte(nil), tx.Data...)
}

func (tx *KangarooTransaction) GetNonce() uint64 {
	return tx.Nonce
}

func (tx *KangarooTransaction) GetSigner() key.PublicKey {
	return tx.Signer
}

func (tx *KangarooTransaction) GetValue() *big.Int {
	if tx.Value == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(tx.Value)
}
