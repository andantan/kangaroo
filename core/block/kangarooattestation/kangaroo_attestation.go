package kangarooattestation

import (
	"errors"
	"fmt"
	"github.com/andantan/kangaroo/codec/wrapper"
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/crypto/key"
	kangarooblockpb "github.com/andantan/kangaroo/proto/core/block/pb"
	"google.golang.org/protobuf/proto"
)

type KangarooAttestation struct {
	Digest    hash.Hash
	Signer    key.PublicKey
	Signature key.Signature
}

var _ block.Attestation = (*KangarooAttestation)(nil)

func NewKangarooAttestation(digest hash.Hash, signer key.PublicKey, siganture key.Signature) *KangarooAttestation {
	return &KangarooAttestation{
		Digest:    digest,
		Signer:    signer,
		Signature: siganture,
	}
}

func (a *KangarooAttestation) ToProto() (proto.Message, error) {
	var err error
	var digestBytes []byte

	if a.Digest != nil {
		digestBytes, err = wrapper.WrapHash(a.Digest)
		if err != nil {
			return nil, err
		}
	}

	var signerBytes []byte
	if a.Signer != nil {
		signerBytes, err = wrapper.WrapPublicKey(a.Signer)
		if err != nil {
			return nil, err
		}
	}

	var signatureBytes []byte
	if a.Signature != nil {
		signatureBytes, err = wrapper.WrapSignature(a.Signature)
		if err != nil {
			return nil, err
		}
	}

	return &kangarooblockpb.KangarooAttestation{
		Digest:    digestBytes,
		Signer:    signerBytes,
		Signature: signatureBytes,
	}, nil
}

func (a *KangarooAttestation) FromProto(m proto.Message) error {
	pb, ok := m.(*kangarooblockpb.KangarooAttestation)
	if !ok {
		return errors.New("cannot deserialize protobuf KangarooAttestation")
	}

	unwrappedDigest, err := wrapper.UnwrapHash(pb.Digest)
	if err != nil {
		return err
	}

	unwrappedSigner, err := wrapper.UnwrapPublicKey(pb.Signer)
	if err != nil {
		return err
	}

	unwrappedSignature, err := wrapper.UnwrapSignature(pb.Signature)
	if err != nil {
		return err
	}

	a.Digest = unwrappedDigest
	a.Signer = unwrappedSigner
	a.Signature = unwrappedSignature

	return nil
}

func (a *KangarooAttestation) NewProto() proto.Message {
	return &kangarooblockpb.KangarooAttestation{}
}

func (a *KangarooAttestation) String() string {
	digestStr := "<nil>"
	if a.Digest != nil {
		digestStr = a.Digest.ShortString(8)
	}

	signerStr := "<nil>"
	if a.Signer != nil {
		signerStr = a.Signer.ShortString(8)
	}

	hasSig := "<nil>"
	if a.Signature != nil {
		hasSig = a.Signature.ShortString(8)
	}

	return fmt.Sprintf("Attestation<%s>{Digest: %s, Signer: %s, Signature: %s}",
		a.Type(), digestStr, signerStr, hasSig)
}

func (a *KangarooAttestation) Type() string {
	return block.KangarooAttestationType
}

func (a *KangarooAttestation) Verify() bool {
	if a.Digest == nil {
		return false
	}

	if a.Signer == nil {
		return false
	}

	if a.Signature == nil {
		return false
	}

	return a.Signature.Verify(a.Signer, a.Digest.Bytes())
}

func (a *KangarooAttestation) GetBlockID() hash.Hash {
	return a.Digest
}

func (a *KangarooAttestation) GetSigner() key.PublicKey {
	return a.Signer
}

func (a *KangarooAttestation) GetSignature() key.Signature {
	return a.Signature
}
