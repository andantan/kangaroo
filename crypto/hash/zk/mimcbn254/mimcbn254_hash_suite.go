package mimcbn254

import (
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegisterHashSuite(&MimcBN254HashSuite{})
}

type MimcBN254HashSuite struct{}

var _ hash.HashSuite = (*MimcBN254HashSuite)(nil)

func (_ *MimcBN254HashSuite) Type() string {
	return hash.MimcBN254Type
}

func (_ *MimcBN254HashSuite) Deriver() hash.HashDeriver {
	return &MimcBN254HashDeriver{}
}

func (_ *MimcBN254HashSuite) HashFromBytes(data []byte) (hash.Hash, error) {
	return MimcBN254HashFromBytes(data)
}
