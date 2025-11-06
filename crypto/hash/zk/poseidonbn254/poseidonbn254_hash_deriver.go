package poseidonbn254

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type PoseidonBN254HashDeriver struct{}

var _ hash.HashDeriver = (*PoseidonBN254HashDeriver)(nil)

func (_ *PoseidonBN254HashDeriver) Type() string {
	return hash.PoseidonBN254Type
}

func (_ *PoseidonBN254HashDeriver) Derive(data []byte) hash.Hash {
	if data == nil {
		return &PoseidonBN254Hash{}
	}

	f := poseidon2.NewMerkleDamgardHasher()
	d := f.Sum(data)

	var fe fr.Element
	fe.SetBytes(d)
	hb := fe.Bytes()

	fhb := make([]byte, hash.HashLength)
	copy(fhb[hash.HashLength-len(hb):], hb[:])

	h, err := PoseidonBN254HashFromBytes(fhb[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid poseidon-bn254 sum: %v", err))
	}
	return h
}
