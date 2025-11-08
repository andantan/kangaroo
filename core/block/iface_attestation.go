package block

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	"github.com/andantan/kangaroo/types/format"
)

const (
	KangarooAttestationType = "kangaroo"
)

type Attestation interface {
	codec.ProtoCodec
	format.Stringable
	format.StringTypable
	format.Verifyable

	GetBlockID() hash.Hash
	GetSigner() key.PublicKey
	GetSignature() key.Signature
}

type AttestationSuite interface {
	format.StringTypable

	NewAttestation() Attestation
}
