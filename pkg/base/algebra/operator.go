package algebra

type RightAssociative[InputType, OutputType Element] interface {
	RFold(xs ...InputType) (OutputType, error)
}

type LeftAssociative[InputType, OutputType Element] interface {
	LFold(xs ...InputType) (OutputType, error)
}

type Associative[InputType, OutputType Element] interface {
	RightAssociative[InputType, OutputType]
	LeftAssociative[InputType, OutputType]
}

type UnaryOperator[E Element] EndoFunction[E]
type BinaryOperator[E Element] BiEndoFunction[E]
