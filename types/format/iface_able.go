package format

type Byteable interface {
	Bytes() []byte
}

type Stringable interface {
	String() string
}

type ShortStringable interface {
	ShortString(length int) string
}

type StringTypable interface {
	Type() string
}

type Validatable interface {
	IsValid() bool
}

type Verifyable interface {
	Verify() bool
}
