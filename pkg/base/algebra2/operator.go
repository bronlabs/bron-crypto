package algebra

type Morphism[X, Y any] interface {
	Map(e X) Y
}

type EndoMorphism[X any] Morphism[X, X]

type BiMorphism[X1, X2, Y any] interface {
	Map(e1 X1, e2 X2) Y
}

type BiEndoMorphism[X any] BiMorphism[X, X, X]

type OperatorName string

type Operator interface {
	Name() OperatorName
	Arity() uint
}

type UnaryOperator[E any] interface {
	Operator
	EndoMorphism[E]
}

type BinaryOperator[E any] interface {
	Operator
	BiEndoMorphism[E]
}

type Successor[E any] interface {
	UnaryOperator[E]
	Next(x E) E
}

type Addition[E any] interface {
	BinaryOperator[E]
	Add(x, y E) E
}

type Subtraction[E any] interface {
	BinaryOperator[E]
	Sub(x, y E) E
}

type Multiplication[E any] interface {
	BinaryOperator[E]
	Mul(x, y E) E
}

type Exponentiation[E any] interface {
	BinaryOperator[E]
	Exp(base, exponent E) E
}

type Join[E any] interface {
	BinaryOperator[E]
	Join(x, y E) E
}

type Meet[E any] interface {
	BinaryOperator[E]
	Meet(x, y E) E
}

type Negation[E any] interface {
	UnaryOperator[E]
	Not(x E) E
}

type Conjunction[E any] interface {
	BinaryOperator[E]
	And(x, y E) E
}

type AlternativeDenial[E any] interface {
	BinaryOperator[E]
	Nand(x, y E) E
}

type Disjunction[E any] interface {
	BinaryOperator[E]
	Or(x, y E) E
}

type JointDenial[E any] interface {
	BinaryOperator[E]
	Nor(x, y E) E
}

type ExclusiveDisjunction[E any] interface {
	BinaryOperator[E]
	Xor(x, y E) E
}
