package properties

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func NewLowLevelGroupalPropertySuite[E impl.GroupElementPtrLowLevel[E, T], T any](
	t *testing.T,
	elementGen *rapid.Generator[E],
	isCommutative bool,
) *GroupalLowLevel[E, T] {
	t.Helper()

	return &GroupalLowLevel[E, T]{
		MonoidalLowLevel: *NewLowLevelMonoidalPropertySuite(t, elementGen, isCommutative),
	}
}

type GroupalLowLevel[E impl.GroupElementPtrLowLevel[E, T], T any] struct {
	MonoidalLowLevel[E, T]
}

func (p *GroupalLowLevel[E, T]) CheckAll(t *testing.T) {
	t.Helper()
	p.MonoidalLowLevel.CheckAll(t)
	t.Run("have additive inverse", p.CanNegate)
	t.Run("can subtract", p.CanSubtract)
}

func (p *GroupalLowLevel[E, T]) CanNegate(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, negA T
		x := p.g.Draw(t, "x")
		E(&a).Set(x)
		E(&negA).Neg(E(&a))
		E(&a).Add(E(&a), E(&negA))
		require.Equal(t, ct.True, E(&a).IsZero())
	})
}

func (p *GroupalLowLevel[E, T]) CanSubtract(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, aMinusB, aMinusBPlusB T
		x := p.g.Draw(t, "x")
		y := p.g.Draw(t, "y")
		E(&a).Set(x)
		E(&b).Set(y)

		E(&aMinusB).Sub(E(&a), E(&b))
		E(&aMinusBPlusB).Add(E(&aMinusB), E(&b))

		require.Equal(t, ct.True, E(&a).Equal(E(&aMinusBPlusB)))
	})
}
