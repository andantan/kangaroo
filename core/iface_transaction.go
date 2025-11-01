package core

import (
	kangaroocodec "github.com/andantan/kangaroo/codec"
	kangaroohash "github.com/andantan/kangaroo/crypto/hash"
)

type Transaction interface {
	kangaroohash.Hashable
	kangaroocodec.ProtoCodec

	Verify(hasher kangaroohash.HashDeriver) error
	Type() string
}
