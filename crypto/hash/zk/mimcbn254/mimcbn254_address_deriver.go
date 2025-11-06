package mimcbn254

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type MimcBN254AddressDeriver struct{}

var _ hash.AddressDeriver = (*MimcBN254AddressDeriver)(nil)

func (_ *MimcBN254AddressDeriver) Type() string {
	return hash.MimcBN254Type
}

func (_ *MimcBN254AddressDeriver) Derive(data []byte) hash.Address {
	if data == nil {
		return &MimcBN254Address{}
	}

	f := mimc.NewMiMC()
	d := f.Sum(data)

	var fe fr.Element
	fe.SetBytes(d)
	hb := fe.Bytes()

	fhb := make([]byte, hash.HashLength)
	copy(fhb[hash.HashLength-len(hb):], hb[:])

	start := hash.HashLength - hash.AddressLength
	ab := fhb[start:]
	h, err := MimcBN254AddressFromBytes(ab)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create address from valid poseidon-bn254 sum: %v", err))
	}
	return h
}
