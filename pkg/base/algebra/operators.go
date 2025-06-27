package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
)

type (
	Operand[E any]      aimpl.Operand[E]
	MaybeOperand[E any] aimpl.MaybeOperand[E]

	DualOperand[E any]      aimpl.DualOperand[E]
	MaybeDualOperand[E any] aimpl.MaybeDualOperand[E]

	Summand[E any]      aimpl.Summand[E]
	MaybeSummand[E any] aimpl.MaybeSummand[E]

	Minuend[E any]      aimpl.Minuend[E]
	MaybeMinuend[E any] aimpl.MaybeMinuend[E]

	Multiplicand[E any]      aimpl.Multiplicand[E]
	MaybeMultiplicand[E any] aimpl.MaybeMultiplicand[E]

	Dividend[E any]      aimpl.Dividend[E]
	MaybeDividend[E any] aimpl.MaybeDividend[E]

	ExponentiationBase[B, E any]      aimpl.ExponentiationBase[B, E]
	MaybeExponentiationBase[B, E any] aimpl.MaybeExponentiationBase[B, E]

	Conjunct[E any]      aimpl.Conjunct[E]
	MaybeConjunct[E any] aimpl.MaybeConjunct[E]

	Disjunct[E any]      aimpl.Disjunct[E]
	MaybeDisjunct[E any] aimpl.MaybeDisjunct[E]

	ExclusiveDisjunct[E any]      aimpl.ExclusiveDisjunct[E]
	MaybeExclusiveDisjunct[E any] aimpl.MaybeExclusiveDisjunct[E]

	ArithmeticNegand[E any]      aimpl.ArithmeticNegand[E]
	MaybeArithmeticNegand[E any] aimpl.MaybeArithmeticNegand[E]

	Inversand[E any]      aimpl.Inversand[E]
	MaybeInversand[E any] aimpl.MaybeInversand[E]

	BooleanNegand[E any]      aimpl.BooleanNegand[E]
	MaybeBooleanNegand[E any] aimpl.MaybeBooleanNegand[E]
)

type Homomorphism[E1 SemiGroupElement[E1], E2 SemiGroupElement[E2]] func(E1) E2

type HomomorphicLike[T any, TV GroupElement[TV]] interface {
	base.Transparent[TV]
	aimpl.Operand[T]
	base.Equatable[T]
}

type AdditivelyHomomorphicLike[T HomomorphicLike[T, TV], TV AdditiveGroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	aimpl.Summand[T]
}

type MultiplicativelyHomomorphicLike[T HomomorphicLike[T, TV], TV MultiplicativeGroupElement[TV]] interface {
	HomomorphicLike[T, TV]
	aimpl.Multiplicand[T]
}

func IsAdditiveObject[E any](e E) bool {
	_, ok := any(e).(Summand[E])
	return ok
}

func IsMultiplicativeObject[E any](e E) bool {
	_, ok := any(e).(Multiplicand[E])
	return ok
}
