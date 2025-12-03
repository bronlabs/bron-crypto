package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewNumericalPropertySuite[
	N algebra.NumericStructure[E],
	E algebra.Numeric[E],
](
	t *testing.T, n N, g *rapid.Generator[E],
) *Numerical[N, E] {
	t.Helper()
	require.NotNil(t, g, "generator must not be nil")
	return &Numerical[N, E]{
		Structural: *NewStructuralPropertySuite(t, n, g),
	}
}

type Numerical[N algebra.NumericStructure[E], E algebra.Numeric[E]] struct {
	Structural[N, E]
}

func (n *Numerical[N, E]) CheckAll(t *testing.T) {
	t.Helper()
	n.Structural.CheckAll(t)
	t.Run("FromBytesBERoundTrip", n.FromBytesBERoundTrip)
}

func (n *Numerical[N, E]) FromBytesBERoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := n.g.Draw(t, "a")
		bb := a.BytesBE()
		aReconstructed, err := n.st.FromBytesBE(bb)
		require.NoError(t, err)
		require.True(t, a.Equal(aReconstructed))
	})
}

// ******************** NPlusLike.

func NewNPlusLikePropertySuite[N algebra.NPlusLike[E], E algebra.NatPlusLike[E]](
	t *testing.T, n N, g *rapid.Generator[E],
) *NPlusLike[N, E] {
	t.Helper()
	return &NPlusLike[N, E]{
		SemiRingal: *NewSemiRingalPropertySuite(t, n, g, true, true, false),
		Numerical:  *NewNumericalPropertySuite(t, n, g),
	}
}

type NPlusLike[N algebra.NPlusLike[E], E algebra.NatPlusLike[E]] struct {
	SemiRingal[N, E]
	Numerical[N, E]
}

func (n *NPlusLike[N, E]) CheckAll(t *testing.T) {
	t.Helper()
	n.SemiRingal.CheckAll(t)
	n.Numerical.CheckAll(t)
	t.Run("IsOddIsEvenExclusive", n.IsOddIsEvenExclusive)
	t.Run("FromCardinalRoundTrip", n.FromCardinalRoundTrip)
}

func (n *NPlusLike[N, E]) IsOddIsEvenExclusive(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := n.SemiRingal.HemiRingal.AdditiveSemiGroupal.g.Draw(t, "a")
		require.True(t, a.IsOdd() != a.IsEven(), "IsOdd and IsEven should be mutually exclusive")
	})
}

func (n *NPlusLike[N, E]) FromCardinalRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := n.SemiRingal.HemiRingal.AdditiveSemiGroupal.g.Draw(t, "a")
		cardinal := a.Cardinal()
		reconstructed, err := n.st.FromCardinal(cardinal)
		require.NoError(t, err)
		require.True(t, a.Equal(reconstructed))
	})
}

// ******************** NLike.

func NewNLikePropertySuite[N algebra.NLike[E], E algebra.NatLike[E]](
	t *testing.T, n N, g *rapid.Generator[E],
) *NLike[N, E] {
	t.Helper()
	return &NLike[N, E]{
		NPlusLike:             *NewNPlusLikePropertySuite(t, n, g),
		EuclideanSemiDomainal: *NewEuclideanSemiDomainalPropertySuite(t, n, g, true, true),
	}
}

type NLike[N algebra.NLike[E], E algebra.NatLike[E]] struct {
	NPlusLike[N, E]
	EuclideanSemiDomainal[N, E]
}

func (n *NLike[N, E]) CheckAll(t *testing.T) {
	t.Helper()
	n.NPlusLike.CheckAll(t)
	n.EuclideanSemiDomainal.CheckAll(t)
	t.Run("IsPositiveOrZero", n.IsPositiveOrZero)
}

func (n *NLike[N, E]) IsPositiveOrZero(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := n.NPlusLike.SemiRingal.HemiRingal.AdditiveSemiGroupal.g.Draw(t, "a")
		require.True(t, a.IsPositive() || a.IsZero(), "natural number should be positive or zero")
		require.True(t, a.IsPositive() != a.IsZero(), "IsPositive and IsZero should be mutually exclusive")
	})
}

// ******************** ZLike.

func NewZLikePropertySuite[Z algebra.ZLike[E], E algebra.IntLike[E]](
	t *testing.T, z Z, g *rapid.Generator[E],
) *ZLike[Z, E] {
	t.Helper()
	return &ZLike[Z, E]{
		EuclideanDomainal: *NewEuclideanDomainalPropertySuite(t, z, g, true, true),
	}
}

type ZLike[Z algebra.ZLike[E], E algebra.IntLike[E]] struct {
	EuclideanDomainal[Z, E]
}

func (z *ZLike[Z, E]) CheckAll(t *testing.T) {
	t.Helper()
	z.EuclideanDomainal.CheckAll(t)
	t.Run("FromCardinalRoundTrip", z.FromCardinalRoundTrip)
	t.Run("SignProperties", z.SignProperties)
}

func (z *ZLike[Z, E]) FromCardinalRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := z.EuclideanDomainal.EuclideanSemiDomainal.Rigal.AdditiveMonoidal.g.Filter(func(x E) bool {
			return !x.IsNegative()
		}).Draw(t, "a")
		cardinal := a.Cardinal()
		reconstructed, err := z.st.FromCardinal(cardinal)
		require.NoError(t, err)
		require.True(t, a.Equal(reconstructed))
	})
}

func (z *ZLike[Z, E]) SignProperties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := z.EuclideanDomainal.EuclideanSemiDomainal.Rigal.AdditiveMonoidal.g.Draw(t, "a")

		// Exactly one of IsPositive, IsNegative, IsZero should be true
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
}

// ******************** ZModLike.

func NewZModLikalPropertySuite[Z algebra.ZModLike[E], E algebra.UintLike[E]](
	t *testing.T, z Z, g *rapid.Generator[E],
) *ZModLikal[Z, E] {
	t.Helper()
	return &ZModLikal[Z, E]{
		Ringal: *NewRingalPropertySuite(t, z, g, true, true),
		NLike:  *NewNLikePropertySuite(t, z, g),
	}
}

type ZModLikal[Z algebra.ZModLike[E], E algebra.UintLike[E]] struct {
	Ringal[Z, E]
	NLike[Z, E]
}

func (z *ZModLikal[Z, E]) CheckAll(t *testing.T) {
	t.Helper()
	z.Ringal.CheckAll(t)
	z.NLike.CheckAll(t)
	t.Run("FromBytesBEReduceWorks", z.FromBytesBEReduceWorks)
}

func (z *ZModLikal[Z, E]) FromBytesBEReduceWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := z.Ringal.Rigal.AdditiveMonoidal.g.Draw(t, "a")
		bb := a.BytesBE()
		reduced, err := z.st.FromBytesBEReduce(bb)
		require.NoError(t, err)
		require.True(t, a.Equal(reduced), "FromBytesBEReduce of canonical bytes should equal original")
	})
}

// ******************** PrimeField.

func NewPrimeFieldalPropertySuite[F algebra.PrimeField[E], E algebra.PrimeFieldElement[E]](
	t *testing.T, f F, g *rapid.Generator[E],
) *PrimeFieldal[F, E] {
	t.Helper()
	return &PrimeFieldal[F, E]{
		Fieldal:   *NewFieldalPropertySuite(t, f, g, true, true),
		ZModLikal: *NewZModLikalPropertySuite(t, f, g),
		field:     f,
	}
}

type PrimeFieldal[F algebra.PrimeField[E], E algebra.PrimeFieldElement[E]] struct {
	Fieldal[F, E]
	ZModLikal[F, E]
	field F
}

func (f *PrimeFieldal[F, E]) CheckAll(t *testing.T) {
	t.Helper()
	f.Fieldal.CheckAll(t)
	f.ZModLikal.CheckAll(t)
	t.Run("BitLenIsPositive", f.BitLenIsPositive)
	t.Run("FromUint64Works", f.FromUint64Works)
	t.Run("FromWideBytesWorks", f.FromWideBytesWorks)
}

func (f *PrimeFieldal[F, E]) BitLenIsPositive(t *testing.T) {
	t.Parallel()
	require.Greater(t, f.field.BitLen(), 0, "BitLen should be positive")
}

func (f *PrimeFieldal[F, E]) FromUint64Works(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		val := rapid.Uint64().Draw(t, "val")
		elem := f.field.FromUint64(val)
		require.NotNil(t, elem)
	})
}

func (f *PrimeFieldal[F, E]) FromWideBytesWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		size := f.field.WideElementSize()
		require.Greater(t, size, 0, "WideElementSize should be positive")
		bytes := rapid.SliceOfN(rapid.Byte(), size, size).Draw(t, "bytes")
		elem, err := f.field.FromWideBytes(bytes)
		require.NoError(t, err)
		require.NotNil(t, elem)
	})
}
