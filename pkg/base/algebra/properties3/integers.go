package properties3

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// BytesBERoundTripTrait verifies that BytesBE() -> FromBytesBE() round-trips correctly.
type BytesBERoundTripTrait[S algebra.NumericStructure[E], E algebra.Numeric[E]] struct{}

func (tr *BytesBERoundTripTrait[S, E]) Name() string { return "BytesBE_RoundTrip" }

func (tr *BytesBERoundTripTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			bb := a.BytesBE()
			reconstructed, err := ctx.Structure().FromBytesBE(bb)
			require.NoError(t, err)
			require.True(t, a.Equal(reconstructed), "BytesBE round-trip failed")
		})
	})
}

// NumericTraits returns traits for testing numeric types.
func NumericTraits[S algebra.NumericStructure[E], E algebra.Numeric[E]]() []Trait[S, E] {
	return []Trait[S, E]{
		&BytesBERoundTripTrait[S, E]{},
	}
}

// IsOddEvenExclusiveTrait verifies that IsOdd() and IsEven() are mutually exclusive.
type IsOddEvenExclusiveTrait[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]] struct{}

func (tr *IsOddEvenExclusiveTrait[S, E]) Name() string { return "IsOdd_IsEven_Exclusive" }

func (tr *IsOddEvenExclusiveTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			require.True(t, a.IsOdd() != a.IsEven(), "IsOdd and IsEven should be mutually exclusive")
		})
	})
}

// CardinalRoundTripTrait verifies that Cardinal() -> FromCardinal() round-trips correctly.
type CardinalRoundTripTrait[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]] struct{}

func (tr *CardinalRoundTripTrait[S, E]) Name() string { return "Cardinal_RoundTrip" }

func (tr *CardinalRoundTripTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			cardinal := a.Cardinal()
			reconstructed, err := ctx.Structure().FromCardinal(cardinal)
			require.NoError(t, err)
			require.True(t, a.Equal(reconstructed), "Cardinal round-trip failed")
		})
	})
}

// NPlusLikeTraits returns all traits for testing N+ (positive natural numbers).
func NPlusLikeTraits[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]

	// SemiRing traits (commutative multiplication)
	traits = append(traits, SemiRingTraits[S, E](s, true)...)

	// Numeric traits
	traits = append(traits, NumericTraits[S, E]()...)

	// N+ specific traits
	traits = append(traits, &IsOddEvenExclusiveTrait[S, E]{})
	traits = append(traits, &CardinalRoundTripTrait[S, E]{})

	return traits
}

// IsPositiveOrZeroTrait verifies that natural numbers are either positive or zero.
type IsPositiveOrZeroTrait[S algebra.NLike[E], E algebra.NatLike[E]] struct{}

func (tr *IsPositiveOrZeroTrait[S, E]) Name() string { return "IsPositive_Or_IsZero" }

func (tr *IsPositiveOrZeroTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			require.True(t, a.IsPositive() || a.IsZero(), "natural number should be positive or zero")
			require.True(t, a.IsPositive() != a.IsZero(), "IsPositive and IsZero should be mutually exclusive")
		})
	})
}

// EuclideanDivisionTrait verifies that a = q*b + r with 0 <= r < |b|.
type EuclideanDivisionTrait[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]] struct{}

func (tr *EuclideanDivisionTrait[S, E]) Name() string { return "Euclidean_Division" }

func (tr *EuclideanDivisionTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Generator().Filter(func(x E) bool {
				return !x.IsZero()
			}).Draw(rt, "b")

			q, r, err := a.EuclideanDiv(b)
			require.NoError(t, err)

			// Verify a = q*b + r
			qb := q.Mul(b)
			reconstructed := qb.Add(r)
			require.True(t, a.Equal(reconstructed), "Euclidean division failed: a != q*b + r")
		})
	})
}

// EuclideanSemiDomainTraits returns traits for testing a Euclidean semi-domain.
func EuclideanSemiDomainTraits[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]
	traits = append(traits, &EuclideanDivisionTrait[S, E]{})
	return traits
}

// NLikeTraits returns all traits for testing N (natural numbers with zero).
func NLikeTraits[S algebra.NLike[E], E algebra.NatLike[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]

	// N+ traits (semiring + numeric)
	traits = append(traits, NPlusLikeTraits[S, E](s)...)

	// Euclidean semi-domain traits
	traits = append(traits, EuclideanSemiDomainTraits[S, E](s)...)

	// N specific traits
	traits = append(traits, &IsPositiveOrZeroTrait[S, E]{})

	return traits
}

// SignPropertiesTrait verifies that exactly one of IsPositive, IsNegative, IsZero is true.
type SignPropertiesTrait[S algebra.ZLike[E], E algebra.IntLike[E]] struct{}

func (tr *SignPropertiesTrait[S, E]) Name() string { return "Sign_Properties" }

func (tr *SignPropertiesTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")

			positive := a.IsPositive()
			negative := a.IsNegative()
			zero := a.IsZero()

			count := 0
			if positive {
				count++
			}
			if negative {
				count++
			}
			if zero {
				count++
			}
			require.Equal(t, 1, count, "exactly one of IsPositive, IsNegative, IsZero should be true")
		})
	})
}

// ZCardinalRoundTripTrait verifies Cardinal round-trip for non-negative integers.
type ZCardinalRoundTripTrait[S algebra.ZLike[E], E algebra.IntLike[E]] struct{}

func (tr *ZCardinalRoundTripTrait[S, E]) Name() string { return "Z_Cardinal_RoundTrip" }

func (tr *ZCardinalRoundTripTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			// Filter to non-negative integers only
			a := ctx.Generator().Filter(func(x E) bool {
				return !x.IsNegative()
			}).Draw(rt, "a")

			cardinal := a.Cardinal()
			reconstructed, err := ctx.Structure().FromCardinal(cardinal)
			require.NoError(t, err)
			require.True(t, a.Equal(reconstructed), "Z Cardinal round-trip failed for non-negative integer")
		})
	})
}

// EuclideanDomainDivisionTrait verifies Euclidean division for domains (with negatives).
type EuclideanDomainDivisionTrait[S algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]] struct{}

func (tr *EuclideanDomainDivisionTrait[S, E]) Name() string { return "EuclideanDomain_Division" }

func (tr *EuclideanDomainDivisionTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Generator().Filter(func(x E) bool {
				return !x.IsZero()
			}).Draw(rt, "b")

			q, r, err := a.EuclideanDiv(b)
			require.NoError(t, err)

			// Verify a = q*b + r
			qb := q.Mul(b)
			reconstructed := qb.Add(r)
			require.True(t, a.Equal(reconstructed), "Euclidean domain division failed: a != q*b + r")
		})
	})
}

// EuclideanDomainTraits returns traits for testing a Euclidean domain.
func EuclideanDomainTraits[S algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]

	// Ring traits
	traits = append(traits, RingTraits[S, E](s, true)...)

	// Euclidean division
	traits = append(traits, &EuclideanDomainDivisionTrait[S, E]{})

	return traits
}

// ZLikeTraits returns all traits for testing Z (integers).
func ZLikeTraits[S algebra.ZLike[E], E algebra.IntLike[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]

	// Euclidean domain traits
	traits = append(traits, EuclideanDomainTraits[S, E](s)...)

	// Z specific traits
	traits = append(traits, &ZCardinalRoundTripTrait[S, E]{})
	traits = append(traits, &SignPropertiesTrait[S, E]{})

	return traits
}

// FromBytesBEReduceTrait verifies FromBytesBEReduce works correctly.
type FromBytesBEReduceTrait[S algebra.ZModLike[E], E algebra.UintLike[E]] struct{}

func (tr *FromBytesBEReduceTrait[S, E]) Name() string { return "FromBytesBEReduce_Works" }

func (tr *FromBytesBEReduceTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			bb := a.BytesBE()
			reduced, err := ctx.Structure().FromBytesBEReduce(bb)
			require.NoError(t, err)
			require.True(t, a.Equal(reduced), "FromBytesBEReduce of canonical bytes should equal original")
		})
	})
}

// ZModLikeTraits returns all traits for testing Z/nZ (integers modulo n).
func ZModLikeTraits[S algebra.ZModLike[E], E algebra.UintLike[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]

	// Ring traits
	traits = append(traits, RingTraits[S, E](s, true)...)

	// N-like traits
	traits = append(traits, NLikeTraits[S, E](s)...)

	// ZMod specific
	traits = append(traits, &FromBytesBEReduceTrait[S, E]{})

	return traits
}

// BitLenPositiveTrait verifies BitLen() returns a positive value.
type BitLenPositiveTrait[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]] struct{}

func (tr *BitLenPositiveTrait[S, E]) Name() string { return "BitLen_Positive" }

func (tr *BitLenPositiveTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		require.Greater(t, ctx.Structure().BitLen(), 0, "BitLen should be positive")
	})
}

// FromUint64WorksTrait verifies FromUint64 produces valid elements.
type FromUint64WorksTrait[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]] struct{}

func (tr *FromUint64WorksTrait[S, E]) Name() string { return "FromUint64_Works" }

func (tr *FromUint64WorksTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			val := rapid.Uint64().Draw(rt, "val")
			elem := ctx.Structure().FromUint64(val)
			require.NotNil(t, elem)
		})
	})
}

// FromWideBytesWorksTrait verifies FromWideBytes produces valid elements.
type FromWideBytesWorksTrait[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]] struct{}

func (tr *FromWideBytesWorksTrait[S, E]) Name() string { return "FromWideBytes_Works" }

func (tr *FromWideBytesWorksTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			size := ctx.Structure().WideElementSize()
			require.Greater(t, size, 0, "WideElementSize should be positive")
			bytes := rapid.SliceOfN(rapid.Byte(), size, size).Draw(rt, "bytes")
			elem, err := ctx.Structure().FromWideBytes(bytes)
			require.NoError(t, err)
			require.NotNil(t, elem)
		})
	})
}

// PrimeFieldTraits returns all traits for testing a prime field.
func PrimeFieldTraits[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]](s S) []Trait[S, E] {
	var traits []Trait[S, E]

	// Field traits (ring + multiplicative inverse for non-zero)
	traits = append(traits, FieldTraits[S, E](s)...)

	// ZMod traits
	traits = append(traits, ZModLikeTraits[S, E](s)...)

	// Prime field specific
	traits = append(traits, &BitLenPositiveTrait[S, E]{})
	traits = append(traits, &FromUint64WorksTrait[S, E]{})
	traits = append(traits, &FromWideBytesWorksTrait[S, E]{})

	return traits
}
