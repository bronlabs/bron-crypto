package properties4

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// NPlusLikeTheory returns a complete theory for N+ (positive natural numbers).
// N+ is a semiring with numeric and N+-specific properties.
func NPlusLikeTheory[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]]() Theory[S, E] {
	var theory Theory[S, E]

	// SemiRing properties (commutative multiplication)
	theory = theory.AppendTheory(SemiRingTheory[S, E](true))

	// Numeric properties
	theory = theory.Append(NumericProperties[S, E]()...)

	// N+ specific properties
	theory = theory.Append(NPlusLikeProperties[S, E]()...)

	return theory
}

// NLikeTheory returns a complete theory for N (natural numbers with zero).
// N includes all N+ properties plus Euclidean division and zero-related properties.
func NLikeTheory[S algebra.NLike[E], E algebra.NatLike[E]]() Theory[S, E] {
	var theory Theory[S, E]

	// N+ theory
	theory = theory.AppendTheory(NPlusLikeTheory[S, E]())

	// Euclidean semi-domain properties
	theory = theory.Append(EuclideanSemiDomainProperties[S, E]()...)

	// N specific properties
	theory = theory.Append(NLikeProperties[S, E]()...)

	return theory
}

// ZLikeTheory returns a complete theory for Z (integers).
// Z is a Euclidean domain with sign properties.
// Note: Z does not include NumericProperties (BytesBE) as ZLike doesn't extend NumericStructure.
func ZLikeTheory[S algebra.ZLike[E], E algebra.IntLike[E]]() Theory[S, E] {
	var theory Theory[S, E]

	// Ring properties with commutative multiplication
	theory = theory.AppendTheory(RingTheory[S, E](true))

	// Euclidean domain properties
	theory = theory.Append(EuclideanDomainProperties[S, E]()...)

	// Z specific properties
	theory = theory.Append(ZLikeProperties[S, E]()...)

	return theory
}

// ZModLikeTheory returns a complete theory for Z/nZ (integers modulo n).
// This includes ring properties, N-like properties, and ZMod-specific properties.
func ZModLikeTheory[S algebra.ZModLike[E], E algebra.UintLike[E]]() Theory[S, E] {
	var theory Theory[S, E]

	// Ring properties (commutative multiplication)
	theory = theory.AppendTheory(RingTheory[S, E](true))

	// Numeric properties (BytesBE round-trip)
	theory = theory.Append(NumericProperties[S, E]()...)

	// N+ like properties (IsOdd/IsEven, Cardinal)
	theory = theory.Append(NPlusLikeProperties[S, E]()...)

	// N like properties (IsPositive/IsZero)
	theory = theory.Append(NLikeProperties[S, E]()...)

	// Euclidean semi-domain properties
	theory = theory.Append(EuclideanSemiDomainProperties[S, E]()...)

	// ZMod specific properties
	theory = theory.Append(ZModLikeProperties[S, E]()...)

	return theory
}

// PrimeFieldTheory returns a complete theory for a prime field.
// A prime field is a field where elements are integers modulo a prime.
func PrimeFieldTheory[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]]() Theory[S, E] {
	var theory Theory[S, E]

	// ZMod properties
	theory = theory.AppendTheory(ZModLikeTheory[S, E]())

	// Prime field specific properties
	theory = theory.Append(PrimeFieldProperties[S, E]()...)

	return theory
}
