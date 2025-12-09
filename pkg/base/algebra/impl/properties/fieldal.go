package properties

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type FiniteFieldalLowLevel[FPtr impl.FiniteFieldElementPtrLowLevel[FPtr, F], F any] struct {
	RingalLowLevel[FPtr, F]

	gNonZero *rapid.Generator[FPtr]
}

func NewLowLevelFiniteFieldalPropertySuite[FPtr impl.FiniteFieldElementPtrLowLevel[FPtr, F], F any](t *testing.T, elementGen *rapid.Generator[FPtr]) *FiniteFieldalLowLevel[FPtr, F] {
	t.Helper()

	r := NewLowLevelRingalPropertySuite(t, elementGen)
	gNonZero := elementGen.Filter(func(f FPtr) bool {
		return f.IsNonZero() == ct.True
	})
	return &FiniteFieldalLowLevel[FPtr, F]{
		RingalLowLevel: *r,
		gNonZero:       gNonZero,
	}
}

func (s *FiniteFieldalLowLevel[FPtr, F]) MultiplicationIsCommutative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b F
		aPtr := s.g.Draw(t, "a")
		bPtr := s.g.Draw(t, "b")
		FPtr(&a).Set(aPtr)
		FPtr(&b).Set(bPtr)

		var l, r F
		FPtr(&l).Mul(&a, &b)
		FPtr(&r).Mul(&b, &a)
		require.Equal(t, ct.True, FPtr(&l).Equal(&r))
	})
}

func (s *FiniteFieldalLowLevel[FPtr, F]) MultiplicationHasNonZeroInverse(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a F
		aPtr := s.gNonZero.Draw(t, "a")
		FPtr(&a).Set(aPtr)

		var l F
		ok := FPtr(&l).Inv(&a)
		require.Equal(t, ct.True, ok)
		FPtr(&l).Mul(&l, &a)
		require.Equal(t, ct.True, FPtr(&l).IsOne())
	})
}

func (s *FiniteFieldalLowLevel[RPtr, R]) CanDivideByNonZero(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var a, b R
		aPtr := s.g.Draw(t, "a")
		bPtr := s.gNonZero.Draw(t, "b")
		RPtr(&a).Set(aPtr)
		RPtr(&b).Set(bPtr)

		var l R
		ok := RPtr(&l).Div(&a, &b)
		require.Equal(t, ct.True, ok)
		RPtr(&l).Mul(&l, &b)
		require.Equal(t, ct.True, RPtr(&l).Equal(&a))
	})
}

func (s *FiniteFieldalLowLevel[FPtr, F]) CanSerialiseToComponents(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a F
		aPtr := s.g.Draw(t, "a")
		FPtr(&a).Set(aPtr)

		var l F
		data := FPtr(&a).ComponentsBytes()
		ok := FPtr(&l).SetUniformBytes(data...)
		require.Equal(t, ct.True, ok)
		require.Equal(t, ct.True, FPtr(&l).Equal(&a))
	})
}

func (s *FiniteFieldalLowLevel[FPtr, F]) CheckAll(t *testing.T) {
	t.Helper()

	s.RingalLowLevel.CheckAll(t)
	t.Run("multiplication is commutative", s.MultiplicationIsCommutative)
	t.Run("multiplication has non-zero inverse", s.MultiplicationHasNonZeroInverse)
	t.Run("can divide by non-zero", s.CanDivideByNonZero)
	t.Run("can serialise to components", s.CanSerialiseToComponents)
}

type PrimeFieldalLowLevel[FPtr impl.PrimeFieldElementPtrLowLevel[FPtr, F], F any] struct {
	FiniteFieldalLowLevel[FPtr, F]

	gComputationalBytes *rapid.Generator[[]byte]
}

func NewLowLevelPrimeFieldalPropertySuite[FPtr impl.PrimeFieldElementPtrLowLevel[FPtr, F], F any](t *testing.T, g *rapid.Generator[FPtr]) *PrimeFieldalLowLevel[FPtr, F] {
	t.Helper()

	f := NewLowLevelFiniteFieldalPropertySuite(t, g)
	gComputationalBytes := rapid.SliceOfN(rapid.Byte(), base.ComputationalSecurityBytesCeil, base.ComputationalSecurityBytesCeil)
	return &PrimeFieldalLowLevel[FPtr, F]{
		FiniteFieldalLowLevel: *f,
		gComputationalBytes:   gComputationalBytes,
	}
}

func (s *PrimeFieldalLowLevel[FPtr, F]) CanSerialiseToLimbs(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a F
		aPtr := s.g.Draw(t, "a")
		FPtr(&a).Set(aPtr)

		var l F
		limbs := FPtr(&a).Limbs()
		ok := FPtr(&l).SetLimbs(limbs)
		require.Equal(t, ct.True, ok)
		require.Equal(t, ct.True, FPtr(&l).Equal(&a))
	})
}

func (s *PrimeFieldalLowLevel[FPtr, F]) CanSetWideBytes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a F
		aPtr := s.g.Draw(t, "a")
		FPtr(&a).Set(aPtr)

		var l F
		data0 := FPtr(&a).Bytes()
		data1 := s.gComputationalBytes.Draw(t, "data")
		data := slices.Concat(data0, data1)
		ok := FPtr(&l).SetBytesWide(data)
		require.Equal(t, ct.True, ok)
	})
}

func (s *PrimeFieldalLowLevel[FPtr, F]) CheckAll(t *testing.T) {
	t.Helper()

	s.FiniteFieldalLowLevel.CheckAll(t)
	t.Run("can serialise to limbs", s.CanSerialiseToLimbs)
	t.Run("can set wide bytes", s.CanSetWideBytes)
}
