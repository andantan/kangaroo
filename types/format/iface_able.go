package format

type Byteable interface {
	Bytes() []byte
}

type Stringable interface {
	String() string
}

type StringTypable interface {
	Type() string
}

type Validatable interface {
	IsValid() bool
}
