package block

import (
	"github.com/andantan/kangaroo/codec"
	"github.com/andantan/kangaroo/types/format"
)

const (
	KangarooTailType = "kangaroo"
)

type Tail interface {
	codec.ProtoCodec
	format.Stringable
	format.StringTypable
}
