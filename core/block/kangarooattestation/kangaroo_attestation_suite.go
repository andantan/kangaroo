package kangarooattestation

import (
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegistryAttestationSuite(&KangarooAttestationSuite{})
}

type KangarooAttestationSuite struct{}

var _ block.AttestationSuite = (*KangarooAttestationSuite)(nil)

func (s *KangarooAttestationSuite) Type() string {
	return block.KangarooAttestationType
}

func (s *KangarooAttestationSuite) NewAttestation() block.Attestation {
	return &KangarooAttestation{}
}
