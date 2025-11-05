package poseidonbn254

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type PoseidonBN254HashDeriver struct{}

var _ kangaroohash.HashDeriver = (*PoseidonBN254HashDeriver)(nil)

func (_ *PoseidonBN254HashDeriver) Type() string {
	return kangaroohash.PoseidonBN254Type
}

func (_ *PoseidonBN254HashDeriver) Derive(data []byte) kangaroohash.Hash {
	f := poseidon2.NewMerkleDamgardHasher()
	d := f.Sum(data)
	
	var fe fr.Element
	fe.SetBytes(d)
	hb := fe.Bytes()

	fhb := make([]byte, kangaroohash.HashLength)
	copy(fhb[kangaroohash.HashLength-len(hb):], hb[:])

	h, err := PoseidonBN254HashFromBytes(fhb[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid poseidon-bn254 sum: %v", err))
	}
	return h
}
