package mimcbn254

import (
	"fmt"
	"github.com/andantan/kangaroo/crypto/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type MimcBN254HashDeriver struct{}

var _ hash.HashDeriver = (*MimcBN254HashDeriver)(nil)

func (_ *MimcBN254HashDeriver) Type() string {
	return hash.MimcBN254Type
}

func (_ *MimcBN254HashDeriver) Derive(data []byte) hash.Hash {
	if data == nil {
		return &MimcBN254Hash{}
	}

	f := mimc.NewMiMC()
	d := f.Sum(data)

	var fe fr.Element
	fe.SetBytes(d)
	hb := fe.Bytes()

	fhb := make([]byte, hash.HashLength)
	copy(fhb[hash.HashLength-len(hb):], hb[:])

	h, err := MimcBN254HashFromBytes(fhb[:])
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to create hash from valid mimc-bn254 sum: %v", err))
	}
	return h
}
