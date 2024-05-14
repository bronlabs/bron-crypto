package algebra

type RightAssociative[E Element] interface {
	RFold(xs ...E) (E, error)
}

type LeftAssociative[E Element] interface {
	LFold(xs ...E) (E, error)
}

type Associative[E Element] interface {
	RightAssociative[E]
	LeftAssociative[E]
}

type Operator string

type UnaryOperator[E Element] interface {
	Name() Operator
	EndoFunction[E]
}
type BinaryOperator[E Element] interface {
	Name() Operator
	BiEndoFunction[E]
	LeftAssociative[E]
}
