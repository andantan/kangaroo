package kangaroobody

import (
	"github.com/andantan/kangaroo/core/block"
	"github.com/andantan/kangaroo/registry"
)

func init() {
	registry.RegistryBodySuite(&KangarooBodySuite{})
}

type KangarooBodySuite struct{}

var _ block.BodySuite = (*KangarooBodySuite)(nil)

func (s *KangarooBodySuite) Type() string {
	return block.KangarooBodyType
}

func (s *KangarooBodySuite) NewBody() block.Body {
	return &KangarooBody{}
}
