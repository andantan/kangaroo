package poseidonbn254

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterHashSuite(&PoseidonBN254HashSuite{})
}

type PoseidonBN254HashSuite struct{}

var _ hash.HashSuite = (*PoseidonBN254HashSuite)(nil)

func (_ *PoseidonBN254HashSuite) Type() string {
	return hash.PoseidonBN254Type
}

func (_ *PoseidonBN254HashSuite) Deriver() hash.HashDeriver {
	return &PoseidonBN254HashDeriver{}
}

func (_ *PoseidonBN254HashSuite) HashFromBytes(data []byte) (hash.Hash, error) {
	return PoseidonBN254HashFromBytes(data)
}
