package poseidonbn254

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type PoseidonBN254AddressDeriver struct{}

var _ hash.AddressDeriver = (*PoseidonBN254AddressDeriver)(nil)

func (_ *PoseidonBN254AddressDeriver) Type() string {
	return hash.PoseidonBN254Type
}

func (_ *PoseidonBN254AddressDeriver) Derive(data []byte) hash.Address {
	if data == nil {
		return &PoseidonBN254Address{}
	}

	f := poseidon2.NewMerkleDamgardHasher()
	d := f.Sum(data)

	var fe fr.Element
	fe.SetBytes(d)
	hb := fe.Bytes()

	fhb := make([]byte, hash.HashLength)
	copy(fhb[hash.HashLength-len(hb):], hb[:])

	start := hash.HashLength - hash.AddressLength
	ab := fhb[start:]
	h, err := PoseidonBN254AddressFromBytes(ab)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create address from valid poseidon-bn254 sum: %v", err))
	}
	return h
}
