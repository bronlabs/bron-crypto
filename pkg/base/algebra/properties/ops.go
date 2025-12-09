package properties

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

type Action[SC algebra.Element[SC], E algebra.Element[E]] struct {
	Name string
	Func func(SC, E) E
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

func ScalarMultiplication[
	E algebra.AdditiveSemiModuleElement[E, RE], RE algebra.SemiRingElement[RE],
]() *Action[RE, E] {
	return &Action[RE, E]{
		Name: "Scalar Multiplication",
		Func: func(s RE, r E) E {
			return r.ScalarMul(s)
		},
	}
}

func ScalarExponentiation[
	E algebra.MultiplicativeSemiModuleElement[E, RE], RE algebra.SemiRingElement[RE],
]() *Action[RE, E] {
	return &Action[RE, E]{
		Name: "Scalar Exponentiation",
		Func: func(s RE, r E) E {
			return r.ScalarExp(s)
		},
	}
}

func AdditiveIdentity[S algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](structure S) *Constant[E] {
	return &Constant[E]{
		Name:  "Additive Identity (Zero)",
		Value: structure.Zero,
	}
}

func MultiplicativeIdentity[S algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](structure S) *Constant[E] {
	return &Constant[E]{
		Name:  "Multiplicative Identity (One)",
		Value: structure.One,
	}
}

func Negation[E algebra.AdditiveGroupElement[E]]() *UnaryOperator[E] {
	return &UnaryOperator[E]{
		Name: "Additive Inverse (Negation)",
		Func: func(a E) E {
			return a.Neg()
		},
	}
}

func Inversion[E algebra.MultiplicativeGroupElement[E]]() *UnaryOperator[E] {
	return &UnaryOperator[E]{
		Name: "Multiplicative Inverse (Inversion)",
		Func: func(a E) E {
			return a.Inv()
		},
	}
}
