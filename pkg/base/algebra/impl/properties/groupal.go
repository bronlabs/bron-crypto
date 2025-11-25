package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewLowLevelGroupalPropertySuite[E impl.GroupElementPtrLowLevel[E, T], T any](
	t *testing.T,
	elementGen *rapid.Generator[E],
	nonZeroElementGen *rapid.Generator[E],
	isCommutative bool,
) *GroupalLowLevel[E, T] {
	return &GroupalLowLevel[E, T]{
		MonoidalLowLevel: *NewLowLevelMonoidalPropertySuite(t, elementGen, nonZeroElementGen, isCommutative),
	}
}

type GroupalLowLevel[E impl.GroupElementPtrLowLevel[E, T], T any] struct {
	MonoidalLowLevel[E, T]
}

func (p *GroupalLowLevel[E, T]) CheckAll(t *testing.T) {
	t.Helper()
	p.MonoidalLowLevel.CheckAll(t)
	t.Run("CanNegate", p.CanNegate)
	t.Run("CanSubtract", p.CanSubtract)
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
		var a, b, negB, aMinusB, aPlusNegB T
		x := p.g.Draw(t, "x")
		y := p.g.Draw(t, "y")
		E(&a).Set(x)
		E(&b).Set(y)
		E(&negB).Neg(E(&b))

		E(&aMinusB).Sub(E(&a), E(&b))
		E(&aPlusNegB).Add(E(&a), E(&negB))

		require.Equal(t, ct.True, E(&aMinusB).Equal(E(&aPlusNegB)))
	})
}
