package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

type (
	NAry[C any]                = crtp.NAry[C]
	Mapping[F, C any]          = crtp.Mapping[F, C]
	Product[P, C any]          = crtp.Product[P, C]
	CoProduct[P, C any]        = crtp.CoProduct[P, C]
	Power[P, C any]            = crtp.Power[P, C]
	TensorProduct[E, C, S any] = crtp.TensorProduct[E, C, S]
	Tensor[E, S any]           = crtp.Tensor[E, S]
)

type (
	Operand[E any]              crtp.Operand[E]
	FixedCapacityOperand[E any] crtp.FixedCapacityOperand[E]

	DualOperand[E any]              crtp.DualOperand[E]
	FixedCapacityDualOperand[E any] crtp.FixedCapacityDualOperand[E]

	Summand[E any]                   crtp.Summand[E]
	FixedCapacitySummand[E any]      crtp.FixedCapacitySummand[E]
	MaybeSummand[E any]              crtp.MaybeSummand[E]
	MaybeFixedCapacitySummand[E any] crtp.MaybeFixedCapacitySummand[E]

	Minuend[E any]                   crtp.Minuend[E]
	FixedCapacityMinuend[E any]      crtp.FixedCapacityMinuend[E]
	MaybeMinuend[E any]              crtp.MaybeMinuend[E]
	MaybeFixedCapacityMinuend[E any] crtp.MaybeFixedCapacityMinuend[E]

	Multiplicand[E any]                   crtp.Multiplicand[E]
	FixedCapacityMultiplicand[E any]      crtp.FixedCapacityMultiplicand[E]
	MaybeMultiplicand[E any]              crtp.MaybeMultiplicand[E]
	MaybeFixedCapacityMultiplicand[E any] crtp.MaybeFixedCapacityMultiplicand[E]

	Dividend[E any]                   crtp.Dividend[E]
	FixedCapacityDividend[E any]      crtp.FixedCapacityDividend[E]
	MaybeDividend[E any]              crtp.MaybeDividend[E]
	MaybeFixedCapacityDividend[E any] crtp.MaybeFixedCapacityDividend[E]

	ExponentiationBase[B, E any]                   crtp.ExponentiationBase[B, E]
	FixedCapacityExponentiationBase[B, E any]      crtp.FixedCapacityExponentiationBase[B, E]
	MaybeExponentiationBase[B, E any]              crtp.MaybeExponentiationBase[B, E]
	MaybeFixedCapacityExponentiationBase[B, E any] crtp.MaybeFixedCapacityExponentiationBase[B, E]

	IntegerExponentiationBase[B, I any]                   crtp.IntegerExponentiationBase[B, I]
	FixedCapacityIntegerExponentiationBase[B, I any]      crtp.FixedCapacityIntegerExponentiationBase[B, I]
	MaybeIntegerExponentiationBase[B, I any]              crtp.MaybeIntegerExponentiationBase[B, I]
	MaybeFixedCapacityIntegerExponentiationBase[B, I any] crtp.MaybeFixedCapacityIntegerExponentiationBase[B, I]

	Residuand[M, Q any] crtp.Residuand[M, Q]

	Conjunct[E any]      crtp.Conjunct[E]
	MaybeConjunct[E any] crtp.MaybeConjunct[E]

	Disjunct[E any]      crtp.Disjunct[E]
	MaybeDisjunct[E any] crtp.MaybeDisjunct[E]

	ExclusiveDisjunct[E any]      crtp.ExclusiveDisjunct[E]
	MaybeExclusiveDisjunct[E any] crtp.MaybeExclusiveDisjunct[E]

	ArithmeticNegand[E any]      crtp.ArithmeticNegand[E]
	MaybeArithmeticNegand[E any] crtp.MaybeArithmeticNegand[E]

	Inversand[E any]      crtp.Inversand[E]
	MaybeInversand[E any] crtp.MaybeInversand[E]

	BooleanNegand[E any]      crtp.BooleanNegand[E]
	MaybeBooleanNegand[E any] crtp.MaybeBooleanNegand[E]

	Shiftable[E, S any]      crtp.Shiftable[E, S]
	MaybeShiftable[E, S any] crtp.MaybeShiftable[E, S]

	LeftBitwiseShiftable[E any]            crtp.LeftBitwiseShiftable[E]
	FixedLengthLeftBitwiseShiftable[E any] crtp.FixedLengthLeftBitwiseShiftable[E]

	RightBitwiseShiftable[E any]            crtp.RightBitwiseShiftable[E]
	FixedLengthRightBitwiseShiftable[E any] crtp.FixedLengthRightBitwiseShiftable[E]

	Resizable[E, C any]      crtp.Resizable[E, C]
	ResizableCapacity[E any] crtp.ResizableCapacity[E]
)

type Homomorphism[E2 SemiGroupElement[E2], E1 SemiGroupElement[E1]] func(E1) E2

type HomomorphicLike[T any, TV SemiGroupElement[TV]] interface {
	base.Transparent[TV]
	crtp.Operand[T]
	base.Equatable[T]
}

type HomomorphicSummand[T any] interface {
	HomAdd(T) T
}

type HomomorphicMinued[T any] interface {
	HomSub(T) T
}

type HomomorphicNegand[T any] interface {
	HomNeg() T
}

type AdditivelyHomomorphicLike[T HomomorphicLike[T, TV], TV AdditiveSemiGroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	crtp.Summand[T]
}

type AdditivelyHomomorphicLikeInCoDomain[T HomomorphicLike[T, TV], TV GroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	HomomorphicSummand[T]
}

type MultiplicativelyHomomorphicLike[T HomomorphicLike[T, TV], TV MultiplicativeSemiGroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	crtp.Multiplicand[T]
}

func Operator[E Operand[E]](a, b E) E {
	return a.Op(b)
}

func FixedCapacityOperator[E FixedCapacityOperand[E]](a E, b E, cap int) E {
	return a.OpCap(b, cap)
}

func DualOperator[E DualOperand[E]](a, b E) E {
	return a.OtherOp(b)
}

func FixedCapacityDualOperator[E FixedCapacityDualOperand[E]](a E, b E, cap int) E {
	return a.OtherOpCap(b, cap)
}

func Addition[E Summand[E]](a, b E) E {
	return a.Add(b)
}

func FixedCapacityAddition[E FixedCapacitySummand[E]](a E, b E, cap int) E {
	return a.AddCap(b, cap)
}

func MaybeAddition[E MaybeSummand[E]](a, b E) (E, error) {
	return a.TryAdd(b)
}

func MaybeFixedCapacityAddition[E MaybeFixedCapacitySummand[E]](a E, b E, cap int) (E, error) {
	return a.TryAddCap(b, cap)
}

func Subtraction[E Minuend[E]](a, b E) E {
	return a.Sub(b)
}

func FixedCapacitySubtraction[E FixedCapacityMinuend[E]](a E, b E, cap int) E {
	return a.SubCap(b, cap)
}
func MaybeSubtraction[E MaybeMinuend[E]](a, b E) (E, error) {
	return a.TrySub(b)
}

func MaybeFixedCapacitySubtraction[E MaybeFixedCapacityMinuend[E]](a E, b E, cap int) (E, error) {
	return a.TrySubCap(b, cap)
}

func Multiplication[E Multiplicand[E]](a, b E) E {
	return a.Mul(b)
}

func FixedCapacityMultiplication[E FixedCapacityMultiplicand[E]](a E, b E, cap int) E {
	return a.MulCap(b, cap)
}

func MaybeMultiplication[E MaybeMultiplicand[E]](a, b E) (E, error) {
	return a.TryMul(b)
}

func MaybeFixedCapacityMultiplication[E MaybeFixedCapacityMultiplicand[E]](a E, b E, cap int) (E, error) {
	return a.TryMulCap(b, cap)
}

func Division[E Dividend[E]](a, b E) E {
	return a.Div(b)
}

func FixedCapacityDivision[E FixedCapacityDividend[E]](a E, b E, cap int) E {
	return a.DivCap(b, cap)
}

func MaybeDivision[E MaybeDividend[E]](a, b E) (E, error) {
	return a.TryDiv(b)
}

func MaybeFixedCapacityDivision[E MaybeFixedCapacityDividend[E]](a E, b E, cap int) (E, error) {
	return a.TryDivCap(b, cap)
}

func Modulo[E Residuand[M, Q], M Element[M], Q Residue[Q, M]](x E, m M) (Q, error) {
	return x.Mod(m)
}

func Exponentiate[A ExponentiationBase[A, E], E Element[E]](base A, exponent E) A {
	return base.Exp(exponent)
}

func FixedCapacityExponentiate[A FixedCapacityExponentiationBase[A, E], E Element[E]](base A, exponent E, cap int) A {
	return base.ExpCap(exponent, cap)
}

func MaybeExponentiate[A MaybeExponentiationBase[A, E], E Element[E]](base A, exponent E) (A, error) {
	return base.TryExp(exponent)
}

func MaybeFixedCapacityExponentiate[A MaybeFixedCapacityExponentiationBase[A, E], E Element[E]](base A, exponent E, cap int) (A, error) {
	return base.TryExpCap(exponent, cap)
}

func And[E Conjunct[E]](a, b E) E {
	return a.And(b)
}

func MaybeAnd[E MaybeConjunct[E]](a, b E) (E, error) {
	return a.TryAnd(b)
}

func Or[E Disjunct[E]](a, b E) E {
	return a.Or(b)
}

func MaybeOr[E MaybeDisjunct[E]](a, b E) (E, error) {
	return a.TryOr(b)
}

func Xor[E ExclusiveDisjunct[E]](a, b E) E {
	return a.Xor(b)
}

func MaybeXor[E MaybeExclusiveDisjunct[E]](a, b E) (E, error) {
	return a.TryXor(b)
}

func Negate[E ArithmeticNegand[E]](a E) E {
	return a.Neg()
}

func MaybeNegate[E MaybeArithmeticNegand[E]](a E) (E, error) {
	return a.TryNeg()
}

func Invert[E Inversand[E]](a E) E {
	return a.Inv()
}

func MaybeInvert[E MaybeInversand[E]](a E) (E, error) {
	return a.TryInv()
}

func Not[E BooleanNegand[E]](a E) E {
	return a.Not()
}

func MaybeNot[E MaybeBooleanNegand[E]](a E) (E, error) {
	return a.TryNot()
}

func Shift[E Shiftable[E, S], S any](a E, shift S) E {
	return a.Shift(shift)
}

func MaybeShift[E MaybeShiftable[E, S], S any](a E, shift S) (E, error) {
	return a.TryShift(shift)
}

func LeftBitwiseShift[E LeftBitwiseShiftable[E]](a E, shift uint) E {
	return a.Lsh(shift)
}

func FixedLengthLeftBitwiseShift[E FixedLengthLeftBitwiseShiftable[E]](a E, shift uint, cap int) E {
	return a.LshCap(shift, cap)
}

func RightBitwiseShift[E RightBitwiseShiftable[E]](a E, shift uint) E {
	return a.Rsh(shift)
}

func FixedLengthRightBitwiseShift[E FixedLengthRightBitwiseShiftable[E]](a E, shift uint, cap int) E {
	return a.RshCap(shift, cap)
}

func Resize[E Resizable[E, C], C any](a E, cap C) E {
	return a.Resize(cap)
}

func ResizeCapacity[E ResizableCapacity[E]](a E, cap int) E {
	return a.Resize(cap)
}

func IsLessThanOrEqual[E base.Comparable[E]](lhs, rhs E) bool {
	return lhs.IsLessThanOrEqual(rhs)
}

func Compare[E base.WithInternalCompareMethod[E]](lhs, rhs E) base.Ordering {
	return lhs.Compare(rhs)
}

func PartialCompare[E base.WithInternalPartialCompareMethod[E]](lhs, rhs E) base.PartialOrdering {
	return lhs.PartialCompare(rhs)
}

func ScalarOp[E Actable[E, S], S Element[S]](sc S, a E) E {
	return a.ScalarOp(sc)
}

func ScalarMultiply[E AdditivelyActable[E, S], S Element[S]](sc S, a E) E {
	return a.ScalarMul(sc)
}

func ScalarExponentiate[E MultiplicativelyActable[E, S], S Element[S]](sc S, a E) E {
	return a.ScalarExp(sc)
}

func Equal[E base.Equatable[E]](a, b E) bool {
	return a.Equal(b)
}
