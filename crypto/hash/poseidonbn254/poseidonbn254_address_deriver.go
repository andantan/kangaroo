package poseidonbn254

import (
	"fmt"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

type PoseidonBN254AddressDeriver struct{}

var _ kangaroohash.AddressDeriver = (*PoseidonBN254AddressDeriver)(nil)

func (_ *PoseidonBN254AddressDeriver) Type() string {
	return kangaroohash.PoseidonBN254Type
}

func (_ *PoseidonBN254AddressDeriver) Derive(data []byte) kangaroohash.Address {
	f := poseidon2.NewMerkleDamgardHasher()
	d := f.Sum(data)

	var fe fr.Element
	fe.SetBytes(d)
	hb := fe.Bytes()

	fhb := make([]byte, kangaroohash.HashLength)
	copy(fhb[kangaroohash.HashLength-len(hb):], hb[:])

	start := kangaroohash.HashLength - kangaroohash.AddressLength
	ab := fhb[start:]
	h, err := PoseidonBN254AddressFromBytes(ab)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid poseidon-bn254 sum: %v", err))
	}
	return h
}
