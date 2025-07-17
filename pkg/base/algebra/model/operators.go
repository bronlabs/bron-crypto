package model

// import (
// 	"hash/fnv"
// 	"reflect"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// )

// type UnaryOperatorType string
// type BinaryOperatorType string
// type MixedSortedBinaryOperatorType string

// const (
// 	AdditionType             BinaryOperatorType = "addition"
// 	SubtractionType          BinaryOperatorType = "subtraction"
// 	MultiplicationType       BinaryOperatorType = "multiplication"
// 	DivisionType             BinaryOperatorType = "division"
// 	ConjunctionType          BinaryOperatorType = "conjunction"
// 	DisjunctionType          BinaryOperatorType = "disjunction"
// 	ExclusiveDisjunctionType BinaryOperatorType = "exclusive_disjunction"
// 	ArithmeticNegationType   UnaryOperatorType  = "arithmetic_negation"
// 	BooleanNegationType      UnaryOperatorType  = "boolean_negation"
// )

// type UnaryOperator[E Element[E]] struct {
// 	name UnaryOperatorType
// 	op   func(E) E
// }

// func (u UnaryOperator[E]) Name() UnaryOperatorType {
// 	return u.name
// }

// func (u UnaryOperator[E]) IsIdempotent(x E) bool {
// 	return u.op(u.op(x)).Equal(u.op(x))
// }

// func (u UnaryOperator[E]) IsInvolution(x E) bool {
// 	return x.Equal(u.op(u.op(x)))
// }

// func (u UnaryOperator[E]) IsFixedPoint(x E) bool {
// 	return x.Equal(u.op(x))
// }

// func (u UnaryOperator[E]) IsConstant(candidate, x E) bool {
// 	return u.op(x).Equal(candidate)
// }

// func (u UnaryOperator[E]) Equal(v UnaryOperator[E]) bool {
// 	return u.name == v.name && reflect.ValueOf(u.op).Pointer() == reflect.ValueOf(v.op).Pointer()
// }

// func (u UnaryOperator[E]) Apply(x E) E {
// 	return u.op(x)
// }

// func (u UnaryOperator[E]) HashCode() base.HashCode {
// 	h := fnv.New64a()
// 	h.Write([]byte(u.name))
// 	return base.HashCode(h.Sum64())
// }

// func K[E Element[E]](constant E) UnaryOperator[E] {
// 	Kx := func(_ E) E { return constant }
// 	return UnaryOperator[E]{name: "K", op: Kx}
// }

// func I[E Element[E]]() UnaryOperator[E] {
// 	I := func(x E) E { return x }
// 	return UnaryOperator[E]{name: "I", op: I}
// }

// func NewBinaryOperator[E Element[E]](op func(E, E) E) BinaryOperator[E] {
// 	return BinaryOperator[E]{op: op}
// }

// type BinaryOperator[E1 Element[E1]] struct {
// 	name BinaryOperatorType
// 	op   func(E1, E1) E1
// }

// func (f BinaryOperator[E]) HashCode() base.HashCode {
// 	h := fnv.New64a()
// 	h.Write([]byte(f.name))
// 	return base.HashCode(h.Sum64())
// }

// func (f BinaryOperator[E]) Equal(g BinaryOperator[E]) bool {
// 	return f.name == g.name && reflect.ValueOf(f.op).Pointer() == reflect.ValueOf(g.op).Pointer()
// }

// func (f BinaryOperator[E]) Name() BinaryOperatorType {
// 	return f.name
// }

// func (f BinaryOperator[E]) LeftSection(x E) UnaryOperator[E] {
// 	return UnaryOperator[E]{op: func(y E) E { return f.op(x, y) }}
// }

// func (f BinaryOperator[E]) RightSection(x E) UnaryOperator[E] {
// 	return UnaryOperator[E]{op: func(y E) E { return f.op(y, x) }}
// }

// func (f BinaryOperator[E]) LeftPower(x E, n uint) E {
// 	if n == 0 {
// 		panic("power must be greater than or equal to 1")
// 	}
// 	result := x
// 	for i := 1; i < int(n); i++ {
// 		result = f.op(result, x)
// 	}
// 	return result
// }

// func (f BinaryOperator[E]) RightPower(x E, n uint) E {
// 	if n == 0 {
// 		panic("power must be greater than or equal to 1")
// 	}
// 	result := x
// 	for i := 1; i < int(n); i++ {
// 		result = f.op(x, result)
// 	}
// 	return result
// }

// func (f BinaryOperator[E]) Apply(x, y E) E {
// 	return f.op(x, y)
// }

// func (f BinaryOperator[E]) FoldLeft(xs ...E) E {
// 	if len(xs) == 0 {
// 		return *new(E)
// 	}
// 	result := xs[0]
// 	for _, x := range xs[1:] {
// 		result = f.op(result, x)
// 	}
// 	return result
// }

// func (f BinaryOperator[E]) FoldRight(xs ...E) E {
// 	if len(xs) == 0 {
// 		return *new(E)
// 	}
// 	result := xs[len(xs)-1]
// 	for i := len(xs) - 2; i >= 0; i-- {
// 		result = f.op(xs[i], result)
// 	}
// 	return result
// }

// func (f BinaryOperator[E]) IsCommutative(a, b E) bool {
// 	return f.op(a, b).Equal(f.op(b, a))
// }

// func (f BinaryOperator[E]) IsFlexible(x, y E) bool {
// 	return f.op(x, f.op(y, x)).Equal(f.op(f.op(x, y), x))
// }

// func (f BinaryOperator[E]) IsLeftAlternative(x, y E) bool {
// 	return f.op(f.op(x, x), y).Equal(f.op(x, f.op(x, y)))
// }

// func (f BinaryOperator[E]) IsRightAlternative(x, y E) bool {
// 	return f.op(y, f.op(x, x)).Equal(f.op(f.op(y, x), x))
// }

// func (f BinaryOperator[E]) IsAlternative(x, y E) bool {
// 	return f.IsLeftAlternative(x, y) && f.IsRightAlternative(x, y)
// }

// func (f BinaryOperator[E]) IsPowerAssociative(x E, n uint) bool {
// 	left := f.LeftPower(x, n)
// 	right := f.RightPower(x, n)
// 	return left.Equal(right)
// }

// func (f BinaryOperator[E]) IsAssociative(a, b, c E) bool {
// 	return f.FoldLeft(a, b, c).Equal(f.FoldRight(a, b, c))
// }

// func (f BinaryOperator[E]) IsIdempotent(x E) bool {
// 	return f.op(x, x).Equal(x)
// }

// func (f BinaryOperator[E]) IsLeftCancellative(candidate, x, y E) bool {
// 	return materialConditional(f.op(candidate, x).Equal(f.op(candidate, y)), x.Equal(y))
// }

// func (f BinaryOperator[E]) IsRightCancellative(candidate, x, y E) bool {
// 	return materialConditional(f.op(x, candidate).Equal(f.op(y, candidate)), x.Equal(y))
// }

// func (f BinaryOperator[E]) IsCancellative(candidate, x, y E) bool {
// 	return f.IsLeftCancellative(candidate, x, y) && f.IsRightCancellative(candidate, x, y)
// }

// func (f BinaryOperator[E]) IsLeftAbsorbing(candidate, x E) bool {
// 	return f.op(candidate, x).Equal(candidate)
// }

// func (f BinaryOperator[E]) IsRightAbsorbing(candidate, x E) bool {
// 	return f.op(x, candidate).Equal(candidate)
// }

// func (f BinaryOperator[E]) IsAbsorbing(candidate, x E) bool {
// 	return f.IsLeftAbsorbing(candidate, x) && f.IsRightAbsorbing(candidate, x)
// }

// func (f BinaryOperator[E]) IsLeftIdentity(candidate, x E) bool {
// 	return f.op(candidate, x).Equal(x)
// }

// func (f BinaryOperator[E]) IsRightIdentity(candidate, x E) bool {
// 	return f.op(x, candidate).Equal(x)
// }

// func (f BinaryOperator[E]) IsIdentity(candidate, x E) bool {
// 	return f.IsLeftIdentity(candidate, x) && f.IsRightIdentity(candidate, x)
// }

// func (f BinaryOperator[E]) IsLeftInverse(candidate, identity, x E) bool {
// 	return f.op(candidate, x).Equal(identity)
// }

// func (f BinaryOperator[E]) IsRightInverse(candidate, identity, x E) bool {
// 	return f.op(x, candidate).Equal(identity)
// }

// func (f BinaryOperator[E]) IsInverse(candidate, identity, x E) bool {
// 	return f.IsLeftInverse(candidate, identity, x) && f.IsRightInverse(candidate, identity, x)
// }

// func (f BinaryOperator[E]) IsLeftDistributive(op BinaryOperator[E], x, y, z E) bool {
// 	return f.op(x, f.op(y, z)).Equal(f.op(f.op(x, y), f.op(x, z)))
// }

// func (f BinaryOperator[E]) IsRightDistributive(op BinaryOperator[E], x, y, z E) bool {
// 	return f.op(x, y).Equal(f.op(f.op(x, z), f.op(y, z)))
// }

// func (f BinaryOperator[E]) IsDistributive(op BinaryOperator[E], x, y, z E) bool {
// 	return f.IsLeftDistributive(op, x, y, z) && f.IsRightDistributive(op, x, y, z)
// }

// type MixedSortedBinaryOperator[E1 Element[E1], E2 Element[E2]] struct {
// 	name MixedSortedBinaryOperatorType
// 	op2  func(E1, E2) E2
// 	op1  func(E1, E2) E1
// }

// func (f MixedSortedBinaryOperator[E1, E2]) IsLeftDistributive(op BinaryOperator[E2], r E1, x, y E2) bool {
// 	return f.op2(r, op.Apply(x, y)).Equal(op.Apply(f.op2(r, x), f.op2(r, y)))
// }

// func (f MixedSortedBinaryOperator[E1, E2]) IsRightDistributive(op BinaryOperator[E1], r, s E1, x E2) bool {
// 	return f.op1(op.Apply(r, s), x).Equal(op.Apply(f.op1(r, x), f.op1(s, x)))
// }

// func (f MixedSortedBinaryOperator[E1, E2]) Apply(x E1, y E2) E2 {
// 	return f.op2(x, y)
// }

// func (f MixedSortedBinaryOperator[E1, E2]) Name() MixedSortedBinaryOperatorType {
// 	return f.name
// }

// type Composition[E Element[E]] = UnaryOperator[E]

// func B[E Element[E]](f, g UnaryOperator[E]) Composition[E] {
// 	return UnaryOperator[E]{op: func(x E) E {
// 		return f.op(g.op(x))
// 	}}
// }

// type Inversand[E Element[E]] interface {
// 	Element[E]
// 	Inv() E
// }
// type Inversion[E Inversand[E]] = UnaryOperator[E]

// func Invert[E Inversand[E]](a E) E {
// 	return a.Inv()
// }

// type Operand[E Element[E]] interface {
// 	Element[E]
// 	Op(E) E
// }

// func Operate[E Operand[E]](a, b E) E {
// 	return a.Op(b)
// }

// type Summand[E Element[E]] interface {
// 	Element[E]
// 	Add(E) E
// }

// func Addition[E Summand[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: AdditionType,
// 		op: func(a, b E) E {
// 			return a.Add(b)
// 		},
// 	}
// }

// type Minuend[E Element[E]] interface {
// 	Element[E]
// 	Sub(E) E
// }

// func Subtraction[E Minuend[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: SubtractionType,
// 		op: func(minued, subterhand E) E {
// 			return minued.Sub(subterhand)
// 		},
// 	}
// }

// type Multiplicand[E Element[E]] interface {
// 	Element[E]
// 	Mul(E) E
// }

// func Multiplication[E Multiplicand[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: MultiplicationType,
// 		op: func(a, b E) E {
// 			return a.Mul(b)
// 		},
// 	}
// }

// type Dividend[E Element[E]] interface {
// 	Element[E]
// 	Div(E) E
// }

// func Division[E Dividend[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: DivisionType,
// 		op: func(dividend, divisor E) E {
// 			return dividend.Div(divisor)
// 		},
// 	}
// }

// type Conjunct[E Element[E]] interface {
// 	Element[E]
// 	And(E) E
// }

// func Conjunction[E Conjunct[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: ConjunctionType,
// 		op: func(a, b E) E {
// 			return a.And(b)
// 		},
// 	}
// }

// type Disjunct[E Element[E]] interface {
// 	Element[E]
// 	Or(E) E
// }

// func Disjunction[E Disjunct[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: DisjunctionType,
// 		op: func(a, b E) E {
// 			return a.Or(b)
// 		},
// 	}
// }

// type ExclusiveDisjunct[E Element[E]] interface {
// 	Element[E]
// 	Xor(E) E
// }

// func ExclusiveDisjunction[E ExclusiveDisjunct[E]]() BinaryOperator[E] {
// 	return BinaryOperator[E]{
// 		name: ExclusiveDisjunctionType,
// 		op: func(a, b E) E {
// 			return a.Xor(b)
// 		},
// 	}
// }

// type ArithmeticNegand[E Element[E]] interface {
// 	Element[E]
// 	Neg() E
// }

// func ArithmeticNegation[E ArithmeticNegand[E]]() UnaryOperator[E] {
// 	return UnaryOperator[E]{
// 		name: ArithmeticNegationType,
// 		op: func(a E) E {
// 			return a.Neg()
// 		},
// 	}
// }

// type BooleanNegand[E Element[E]] interface {
// 	Element[E]
// 	Not() E
// }

// func BooleanNegation[E BooleanNegand[E]]() UnaryOperator[E] {
// 	return UnaryOperator[E]{
// 		name: BooleanNegationType,
// 		op: func(a E) E {
// 			return a.Not()
// 		},
// 	}
// }
