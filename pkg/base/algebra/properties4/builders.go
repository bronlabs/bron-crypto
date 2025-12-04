package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"pgregory.net/rapid"
)

// AdditiveGroupModel creates a model for an additive group.
func AdditiveGroupModel[S algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			carrier.Zero,
			func(a E) E { return a.Neg() },
		)).
		WithTheory(AdditiveGroupTheory[S, E]())
}

// RingModel creates a model for a ring.
func RingModel[S algebra.Ring[E], E algebra.RingElement[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
	mulCommutative bool,
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			carrier.Zero,
			func(a E) E { return a.Neg() },
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil,
			mulCommutative,
		)).
		WithTheory(RingTheory[S, E](mulCommutative))
}

// SemiRingModel creates a model for a semiring.
func SemiRingModel[S algebra.SemiRing[E], E algebra.SemiRingElement[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
	mulCommutative bool,
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			nil, // No zero for semiring
			nil, // No negation for semiring
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil,
			mulCommutative,
		)).
		WithTheory(SemiRingTheory[S, E](mulCommutative))
}

// NPlusLikeModel creates a model for N+ (positive natural numbers).
func NPlusLikeModel[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			nil, // No zero in N+
			nil, // No negation in N+
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil,
			true, // Multiplication is commutative
		)).
		WithTheory(NPlusLikeTheory[S, E]())
}

// NLikeModel creates a model for N (natural numbers with zero).
func NLikeModel[S algebra.NLike[E], E algebra.NatLike[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			carrier.Zero,
			nil, // No negation in N
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil,
			true, // Multiplication is commutative
		)).
		WithTheory(NLikeTheory[S, E]())
}

// ZLikeModel creates a model for Z (integers).
func ZLikeModel[S algebra.ZLike[E], E algebra.IntLike[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			carrier.Zero,
			func(a E) E { return a.Neg() },
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil,
			true, // Multiplication is commutative
		)).
		WithTheory(ZLikeTheory[S, E]())
}

// ZModLikeModel creates a model for Z/nZ (integers modulo n).
func ZModLikeModel[S algebra.ZModLike[E], E algebra.UintLike[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			carrier.Zero,
			func(a E) E { return a.Neg() },
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil,
			true, // Multiplication is commutative
		)).
		WithTheory(ZModLikeTheory[S, E]())
}

// PrimeFieldModel creates a model for a prime field.
// Note: Multiplicative inverse is not set because PrimeFieldElement doesn't include Inv().
// Use a custom builder if you need to test multiplicative inverses.
func PrimeFieldModel[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return NewModelFrom(carrier, gen).
		WithAddition(AdditionOp(
			func(a, b E) E { return a.Add(b) },
			carrier.Zero,
			func(a E) E { return a.Neg() },
		)).
		WithMultiplication(MultiplicationOp(
			func(a, b E) E { return a.Mul(b) },
			carrier.One,
			nil, // PrimeFieldElement doesn't include Inv()
			true, // Multiplication is commutative
		)).
		WithTheory(PrimeFieldTheory[S, E]())
}
