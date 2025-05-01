package algebra

import (
	"reflect"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Morphism[E1 Operand[E1], E2 Operand[E2]] func(E1) E2

func (f Morphism[E1, E2]) IsHomomorphism(x, y E1) bool {
	return f(x).Op(f(y)).Equal(f(x.Op(y)))
}

func (f Morphism[E1, E2]) IsEndomorphism() bool {
	return reflect.TypeOf((*E1)(nil)) == reflect.TypeOf((*E2)(nil))
}

func (f Morphism[E1, E2]) IsIsomorphism(inv Morphism[E2, E1], x, y E1) bool {
	return f.IsHomomorphism(x, y) && inv.IsHomomorphism(f(x), f(y)) && inv(f(x)).Equal(x)
}

type Hom[E1 MagmaElement[E1], E2 MagmaElement[E2]] = Morphism[E1, E2]

type Endomorphism[E MagmaElement[E]] = Hom[E, E]

type Isomorphism[E1 MagmaElement[E1], E2 MagmaElement[E2]] interface {
	Mapping() Hom[E1, E2]
	Inverse() Hom[E2, E1]
}

type Automorphism[E MagmaElement[E]] Isomorphism[E, E]

type UnaryOperator[E ds.Equatable[E]] func(E) E

func (u UnaryOperator[E]) IsIdempotent(x E) bool {
	return u(u(x)).Equal(u(x))
}

func (u UnaryOperator[E]) IsInvolution(x E) bool {
	return x.Equal(u(u(x)))
}

func (u UnaryOperator[E]) IsFixedPoint(x E) bool {
	return x.Equal(u(x))
}

type BinaryOperator[E ds.Equatable[E]] func(E, E) E

func (f BinaryOperator[E]) IsCommutative(a, b E) bool {
	return f(a, b).Equal(f(b, a))
}

func (f BinaryOperator[E]) IsAssociative(a, b, c E) bool {
	return f(f(a, b), c).Equal(f(a, f(b, c)))
}

func (f BinaryOperator[E]) IsIdempotent(x E) bool {
	return f(x, x).Equal(x)
}

func (f BinaryOperator[E]) IsLeftCancellative(e, b, c E) bool {
	return implies(f(e, b).Equal(f(e, c)), b.Equal(c))
}

func (f BinaryOperator[E]) IsRightCancellative(e, b, c E) bool {
	return implies(f(b, e).Equal(f(c, e)), b.Equal(c))
}

func (f BinaryOperator[E]) IsAbsorbing(e, a E) bool {
	return f(e, a).Equal(a) && f(a, e).Equal(a)
}

func (f BinaryOperator[E]) IsLeftDistributive(op BinaryOperator[E], x, y, z E) bool {
	return f(x, op(y, z)).Equal(op(f(x, y), f(x, z)))
}

func (f BinaryOperator[E]) IsRightDistributive(op BinaryOperator[E], x, y, z E) bool {
	return f(op(x, y), z).Equal(op(f(x, z), f(y, z)))
}

func (f BinaryOperator[E]) IsDistributive(op BinaryOperator[E], x, y, z E) bool {
	return f.IsLeftDistributive(op, x, y, z) && f.IsRightDistributive(op, x, y, z)
}

type Composition[E ds.Equatable[E]] BinaryOperator[E]

func Compose[F interface {
	UnaryOperator[E]
	ds.Equatable[F]
}, E ds.Equatable[E]](a, b F) UnaryOperator[E] {
	return func(x E) E { return a(b(x)) }
}

func Invert[E interface {
	ds.Equatable[E]
	Inv() E
}](a E) E {
	return a.Inv()
}

type Operand[E any] interface {
	ds.Equatable[E]
	Op(E) E
}

type BiOperand[E any] interface {
	Operand[E]
	OtherOp(E) E
}

func Operate[E Operand[E]](a, b E) E {
	return a.Op(b)
}

type Summand[E Operand[E]] interface {
	Operand[E]
	Add(E) E
}

type Addition[E Summand[E]] BinaryOperator[E]

func Add[E Summand[E]](a, b E) E {
	return a.Add(b)
}

type Multiplicand[E Operand[E]] interface {
	Operand[E]
	Mul(E) E
}

type Multiplication[E Multiplicand[E]] BinaryOperator[E]

func Mul[E Multiplicand[E]](a, b E) E {
	return a.Mul(b)
}

type Conjunct[E Operand[E]] interface {
	Operand[E]
	And(E) E
}

type Conjunction[E Conjunct[E]] BinaryOperator[E]

func And[E Conjunct[E]](a, b E) E {
	return a.And(b)
}

type Disjunct[E Operand[E]] interface {
	Operand[E]
	Or(E) E
}

type Disjunction[E Disjunct[E]] BinaryOperator[E]

func Or[E Disjunct[E]](a, b E) E {
	return a.Or(b)
}

type ExclusiveDisjunct[E Operand[E]] interface {
	Operand[E]
	Xor(E) E
}

type ExclusiveDisjunction[E ExclusiveDisjunct[E]] BinaryOperator[E]

func Xor[E ExclusiveDisjunct[E]](a, b E) E {
	return a.Xor(b)
}

type Negand[E Operand[E]] interface {
	Operand[E]
	Not() E
}

type Negation[E Negand[E]] UnaryOperator[E]

func Not[E Negand[E]](a E) E {
	return a.Not()
}

func implies(p, q bool) bool {
	return !p || q
}
