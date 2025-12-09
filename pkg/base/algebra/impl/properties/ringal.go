package properties

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type RingalLowLevel[RPtr impl.RingElementPtrLowLevel[RPtr, R], R any] struct {
	GroupalLowLevel[RPtr, R]
}

func NewLowLevelRingalPropertySuite[RPtr impl.RingElementPtrLowLevel[RPtr, R], R any](t *testing.T, elementGen *rapid.Generator[RPtr]) *RingalLowLevel[RPtr, R] {
	t.Helper()

	grupal := NewLowLevelGroupalPropertySuite(t, elementGen, true)
	return &RingalLowLevel[RPtr, R]{
		GroupalLowLevel: *grupal,
	}
}

func (s *RingalLowLevel[RPtr, R]) MultiplicationIsAssociate(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c R
		aPtr := s.g.Draw(t, "a")
		bPtr := s.g.Draw(t, "b")
		cPtr := s.g.Draw(t, "c")
		RPtr(&a).Set(aPtr)
		RPtr(&b).Set(bPtr)
		RPtr(&c).Set(cPtr)

		var l, r R
		RPtr(&l).Mul(&a, &b)
		RPtr(&l).Mul(&l, &c)
		RPtr(&r).Mul(&b, &c)
		RPtr(&r).Mul(&a, &r)
		require.Equal(t, ct.True, RPtr(&l).Equal(RPtr(&r)))
	})
}

func (s *RingalLowLevel[RPtr, R]) MultiplicationHasIdentity(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var one, a R
		aPtr := s.g.Draw(t, "a")
		RPtr(&one).SetOne()
		RPtr(&a).Set(aPtr)

		var l, r R
		RPtr(&l).Mul(&a, &one)
		RPtr(&r).Mul(&one, &a)
		require.Equal(t, ct.True, RPtr(&one).IsOne())
		require.Equal(t, ct.True, RPtr(&one).IsNonZero())
		require.Equal(t, ct.False, RPtr(&one).IsZero())
		require.Equal(t, ct.True, RPtr(&l).Equal(&a))
		require.Equal(t, ct.True, RPtr(&r).Equal(&a))
	})
}

func (s *RingalLowLevel[RPtr, R]) MultiplicationIsLeftDistributive(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c R
		aPtr := s.g.Draw(t, "a")
		bPtr := s.g.Draw(t, "b")
		cPtr := s.g.Draw(t, "c")
		RPtr(&a).Set(aPtr)
		RPtr(&b).Set(bPtr)
		RPtr(&c).Set(cPtr)

		var l, r, z R
		RPtr(&l).Add(&b, &c)
		RPtr(&l).Mul(&a, &l)
		RPtr(&z).Mul(&a, &c)
		RPtr(&r).Mul(&a, &b)
		RPtr(&r).Add(&r, &z)
		require.Equal(t, ct.True, RPtr(&l).Equal(&r))
	})
}

func (s *RingalLowLevel[RPtr, R]) MultiplicationIsRightDistributive(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var b, c, a R
		bPtr := s.g.Draw(t, "b")
		cPtr := s.g.Draw(t, "c")
		aPtr := s.g.Draw(t, "a")
		RPtr(&b).Set(bPtr)
		RPtr(&c).Set(cPtr)
		RPtr(&a).Set(aPtr)

		var l, r, z R
		RPtr(&l).Add(&b, &c)
		RPtr(&l).Mul(&l, &a)
		RPtr(&z).Mul(&b, &a)
		RPtr(&r).Mul(&c, &a)
		RPtr(&r).Add(&z, &r)
		require.Equal(t, ct.True, RPtr(&l).Equal(&r))
	})
}

func (s *RingalLowLevel[RPtr, R]) CanSquare(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var a R
		aPtr := s.g.Draw(t, "a")
		RPtr(&a).Set(aPtr)

		var l, r R
		RPtr(&l).Square(&a)
		RPtr(&r).Mul(&a, &a)
		require.Equal(t, ct.True, RPtr(&l).Equal(&r))
	})
}

func (s *RingalLowLevel[RPtr, R]) MaybeHaveMultiplicativeInverse(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var a R
		aPtr := s.g.Draw(t, "a")
		RPtr(&a).Set(aPtr)

		var l, r, one R
		ok := RPtr(&l).Inv(&a)
		if ok == ct.True {
			RPtr(&one).SetOne()
			RPtr(&r).Mul(&l, &a)
			RPtr(&l).Mul(&a, &l)
			require.Equal(t, ct.True, RPtr(&l).Equal(&one))
			require.Equal(t, ct.True, RPtr(&r).Equal(&one))
		}
	})
}

func (s *RingalLowLevel[RPtr, R]) MaybeCanDivide(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var a, b R
		aPtr := s.g.Draw(t, "a")
		bPtr := s.g.Draw(t, "b")
		RPtr(&a).Set(aPtr)
		RPtr(&b).Set(bPtr)

		var l, r R
		ok := RPtr(&l).Div(&a, &b)
		if ok == ct.True {
			RPtr(&r).Mul(&l, &b)
			RPtr(&l).Mul(&b, &l)
			require.Equal(t, ct.True, RPtr(&l).Equal(&a))
			require.Equal(t, ct.True, RPtr(&r).Equal(&a))
		}
	})
}

func (s *RingalLowLevel[RPtr, R]) MaybeHaveSquareRoot(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var a R
		aPtr := s.g.Draw(t, "a")
		RPtr(&a).Set(aPtr)

		var r R
		ok := RPtr(&r).Sqrt(&a)
		if ok == ct.True {
			RPtr(&r).Mul(&r, &r)
			require.Equal(t, ct.True, RPtr(&r).Equal(&a))
		}
	})
}

func (s *RingalLowLevel[RPtr, R]) CheckAll(t *testing.T) {
	t.Helper()

	s.GroupalLowLevel.CheckAll(t)
	t.Run("multiplication is associative", s.MultiplicationIsAssociate)
	t.Run("multiplication has identity", s.MultiplicationHasIdentity)
	t.Run("multiplication is left distributive", s.MultiplicationIsLeftDistributive)
	t.Run("multiplication is right distributive", s.MultiplicationIsRightDistributive)
	t.Run("can square", s.CanSquare)
	t.Run("might have a multiplicative inverse", s.MaybeHaveMultiplicativeInverse)
	t.Run("might divide", s.MaybeCanDivide)
	t.Run("might have a square root", s.MaybeHaveSquareRoot)
}
