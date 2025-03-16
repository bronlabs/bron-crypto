package algebra

import (
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
)

type UnaryOperator[E Element[E]] func(E) E

func (u UnaryOperator[E]) IsIdempotent(x E) bool {
	return u(u(x)).Equal(u(x))
}

func (u UnaryOperator[E]) IsInvolution(x E) bool {
	return x.Equal(u(u(x)))
}

func (u UnaryOperator[E]) IsFixedPoint(x E) bool {
	return x.Equal(u(x))
}

type BinaryOperator[E Operand[E]] func(E, E) E

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

func (f BinaryOperator[E]) IsAborbing(e, a E) bool {
	return f(e, a).Equal(a) && f(a, e).Equal(a)
}

func IsLeftDistributive[E Operand[E]](op1, op2 BinaryOperator[E], x, y, z E) bool {
	return op2(x, op1(y, z)).Equal(op1(op2(x, y), op2(x, z)))
}

func IsRightDistributive[E Operand[E]](op1, op2 BinaryOperator[E], x, y, z E) bool {
	return op2(op1(x, y), z).Equal(op1(op2(x, z), op2(y, z)))
}

func IsDistributive[E Operand[E]](op1, op2 BinaryOperator[E], x, y, z E) bool {
	return IsLeftDistributive(op1, op2, x, y, z) && IsRightDistributive(op1, op2, x, y, z)
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

func Add[E Summand[E]](a, b E) E {
	return a.Add(b)
}

type Multiplicand[E Operand[E]] interface {
	Operand[E]
	Mul(E) E
}

func Mul[E Multiplicand[E]](a, b E) E {
	return a.Mul(b)
}

type Conjunct[E Operand[E]] interface {
	Operand[E]
	And(E) E
}

func And[E Conjunct[E]](a, b E) E {
	return a.And(b)
}

type Disjunct[E Operand[E]] interface {
	Operand[E]
	Or(E) E
}

func Or[E Disjunct[E]](a, b E) E {
	return a.Or(b)
}

type ExclusiveDisjunct[E Operand[E]] interface {
	Operand[E]
	Xor(E) E
}

func Xor[E ExclusiveDisjunct[E]](a, b E) E {
	return a.Xor(b)
}

type Negand[E Operand[E]] interface {
	Operand[E]
	Not() E
}

func Not[E Negand[E]](a E) E {
	return a.Not()
}

func implies(p, q bool) bool {
	return !p || q
}
