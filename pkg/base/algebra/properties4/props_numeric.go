package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// BytesBERoundTripProperty verifies that BytesBE() -> FromBytesBE() round-trips correctly.
func BytesBERoundTripProperty[S algebra.NumericStructure[E], E algebra.Numeric[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "BytesBE_RoundTrip",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				bb := a.BytesBE()
				reconstructed, err := ctx.Carrier().FromBytesBE(bb)
				require.NoError(t, err)
				require.True(t, a.Equal(reconstructed), "BytesBE round-trip failed")
			})
		},
	}
}

// IsOddEvenExclusiveProperty verifies that IsOdd() and IsEven() are mutually exclusive.
func IsOddEvenExclusiveProperty[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "IsOdd_IsEven_Exclusive",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				require.True(t, a.IsOdd() != a.IsEven(), "IsOdd and IsEven should be mutually exclusive")
			})
		},
	}
}

// CardinalRoundTripProperty verifies that Cardinal() -> FromCardinal() round-trips correctly.
func CardinalRoundTripProperty[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Cardinal_RoundTrip",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				cardinal := a.Cardinal()
				reconstructed, err := ctx.Carrier().FromCardinal(cardinal)
				require.NoError(t, err)
				require.True(t, a.Equal(reconstructed), "Cardinal round-trip failed")
			})
		},
	}
}

// IsPositiveOrZeroProperty verifies that natural numbers are either positive or zero.
func IsPositiveOrZeroProperty[S algebra.NLike[E], E algebra.NatLike[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "IsPositive_Or_IsZero",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				require.True(t, a.IsPositive() || a.IsZero(), "natural number should be positive or zero")
				require.True(t, a.IsPositive() != a.IsZero(), "IsPositive and IsZero should be mutually exclusive")
			})
		},
	}
}

// SignPropertiesProperty verifies that exactly one of IsPositive, IsNegative, IsZero is true.
func SignPropertiesProperty[S algebra.ZLike[E], E algebra.IntLike[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Sign_Properties",
		Check: func(t *testing.T, ctx *Context[S, E]) {
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
		},
	}
}

// ZCardinalRoundTripProperty verifies Cardinal round-trip for non-negative integers.
func ZCardinalRoundTripProperty[S algebra.ZLike[E], E algebra.IntLike[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Z_Cardinal_RoundTrip",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				// Filter to non-negative integers only
				a := ctx.Generator().Filter(func(x E) bool {
					return !x.IsNegative()
				}).Draw(rt, "a")

				cardinal := a.Cardinal()
				reconstructed, err := ctx.Carrier().FromCardinal(cardinal)
				require.NoError(t, err)
				require.True(t, a.Equal(reconstructed), "Z Cardinal round-trip failed for non-negative integer")
			})
		},
	}
}

// FromBytesBEReduceProperty verifies FromBytesBEReduce works correctly.
func FromBytesBEReduceProperty[S algebra.ZModLike[E], E algebra.UintLike[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "FromBytesBEReduce_Works",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				bb := a.BytesBE()
				reduced, err := ctx.Carrier().FromBytesBEReduce(bb)
				require.NoError(t, err)
				require.True(t, a.Equal(reduced), "FromBytesBEReduce of canonical bytes should equal original")
			})
		},
	}
}

// BitLenPositiveProperty verifies BitLen() returns a positive value.
func BitLenPositiveProperty[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "BitLen_Positive",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			require.Greater(t, ctx.Carrier().BitLen(), 0, "BitLen should be positive")
		},
	}
}

// FromUint64WorksProperty verifies FromUint64 produces valid elements.
func FromUint64WorksProperty[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "FromUint64_Works",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				val := rapid.Uint64().Draw(rt, "val")
				elem := ctx.Carrier().FromUint64(val)
				require.NotNil(t, elem)
			})
		},
	}
}

// FromWideBytesWorksProperty verifies FromWideBytes produces valid elements.
func FromWideBytesWorksProperty[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "FromWideBytes_Works",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				size := ctx.Carrier().WideElementSize()
				require.Greater(t, size, 0, "WideElementSize should be positive")
				bytes := rapid.SliceOfN(rapid.Byte(), size, size).Draw(rt, "bytes")
				elem, err := ctx.Carrier().FromWideBytes(bytes)
				require.NoError(t, err)
				require.NotNil(t, elem)
			})
		},
	}
}

// NumericProperties returns properties for testing numeric types.
func NumericProperties[S algebra.NumericStructure[E], E algebra.Numeric[E]]() []Property[S, E] {
	return []Property[S, E]{
		BytesBERoundTripProperty[S, E](),
	}
}

// NPlusLikeProperties returns properties specific to N+ (positive natural numbers).
func NPlusLikeProperties[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]]() []Property[S, E] {
	return []Property[S, E]{
		IsOddEvenExclusiveProperty[S, E](),
		CardinalRoundTripProperty[S, E](),
	}
}

// NLikeProperties returns properties specific to N (natural numbers with zero).
func NLikeProperties[S algebra.NLike[E], E algebra.NatLike[E]]() []Property[S, E] {
	return []Property[S, E]{
		IsPositiveOrZeroProperty[S, E](),
	}
}

// ZLikeProperties returns properties specific to Z (integers).
func ZLikeProperties[S algebra.ZLike[E], E algebra.IntLike[E]]() []Property[S, E] {
	return []Property[S, E]{
		SignPropertiesProperty[S, E](),
		ZCardinalRoundTripProperty[S, E](),
	}
}

// ZModLikeProperties returns properties specific to Z/nZ (integers modulo n).
func ZModLikeProperties[S algebra.ZModLike[E], E algebra.UintLike[E]]() []Property[S, E] {
	return []Property[S, E]{
		FromBytesBEReduceProperty[S, E](),
	}
}

// PrimeFieldProperties returns properties specific to prime fields.
func PrimeFieldProperties[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]]() []Property[S, E] {
	return []Property[S, E]{
		BitLenPositiveProperty[S, E](),
		FromUint64WorksProperty[S, E](),
		FromWideBytesWorksProperty[S, E](),
	}
}
