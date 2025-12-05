package properties

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

type Action[S algebra.Element[S], E algebra.Element[E]] struct {
	Name string
	Func func(S, E) E
}

type Constant[E algebra.Element[E]] struct {
	Name  string
	Value func() E
}

type UnaryOperator[E algebra.Element[E]] struct {
	Name string
	Func func(E) E
}

type BinaryOperator[E algebra.Element[E]] struct {
	Name string
	Func func(E, E) E
}

type Predicate[E algebra.Element[E]] struct {
	Name string
	Func func(E) bool
}

type Relation[E algebra.Element[E]] struct {
	Name string
	Func func(E, E) bool
}

func Addition[E interface {
	algebra.Element[E]
	algebra.Summand[E]
}]() *BinaryOperator[E] {
	return &BinaryOperator[E]{
		Name: "Addition",
		Func: func(a, b E) E {
			return a.Add(b)
		},
	}
}

func Multiplication[E interface {
	algebra.Element[E]
	algebra.Multiplicand[E]
}]() *BinaryOperator[E] {
	return &BinaryOperator[E]{
		Name: "Multiplication",
		Func: func(a, b E) E {
			return a.Mul(b)
		},
	}
}

func Equality[E algebra.Element[E]]() *Relation[E] {
	return &Relation[E]{
		Name: "Equality",
		Func: func(a, b E) bool {
			return a.Equal(b)
		},
	}
}
