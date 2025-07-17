package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

const UnboundedCapacity crtp.Capacity = -1

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
	Capacity                    = crtp.Capacity
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

	Residual[M, Q any] crtp.Residual[M, Q]

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

type Homomorphism[E1 SemiGroupElement[E1], E2 SemiGroupElement[E2]] func(E1) E2

type HomomorphicLike[T any, TV GroupElement[TV]] interface {
	base.Transparent[TV]
	crtp.Operand[T]
	base.Equatable[T]
}

type AdditivelyHomomorphicLike[T HomomorphicLike[T, TV], TV AdditiveGroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	crtp.Summand[T]
}

type MultiplicativelyHomomorphicLike[T HomomorphicLike[T, TV], TV MultiplicativeGroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	crtp.Multiplicand[T]
}

func IsAdditiveObject[E any](e E) bool {
	_, ok := any(e).(Summand[E])
	return ok
}

func IsMultiplicativeObject[E any](e E) bool {
	_, ok := any(e).(Multiplicand[E])
	return ok
}
