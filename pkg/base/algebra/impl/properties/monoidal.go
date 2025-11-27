package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewLowLevelMonoidalPropertySuite[E impl.MonoidElementPtrLowLevel[E, T], T any](t *testing.T, g *rapid.Generator[E], isCommutative bool) *MonoidalLowLevel[E, T] {
	t.Helper()
	require.NotNil(t, g, "generator must not be nil")
	return &MonoidalLowLevel[E, T]{
		g:             g,
		isCommutative: isCommutative,
	}
}

type MonoidalLowLevel[E impl.MonoidElementPtrLowLevel[E, T], T any] struct {
	g             *rapid.Generator[E]
	isCommutative bool
}

func (p *MonoidalLowLevel[E, T]) CheckAll(t *testing.T) {
	t.Helper()
	t.Run("CanSet", p.CanSet)
	t.Run("AdditionIsAssociative", p.AdditionIsAssociative)
	t.Run("Double", p.Double)
	t.Run("ZeroIsNeutralElement", p.ZeroIsNeutralElement)
	t.Run("ZeroIsIdentifiable", p.ZeroIsIdentifiable)
	t.Run("CanConditionallySelect", p.CanConditionallySelect)
	t.Run("CanSerializeDeserialize", p.CanSerializeDeserialize)
	t.Run("CanEquate", p.CanEquate)
	if p.isCommutative {
		t.Run("AdditionIsCommutative", p.AdditionIsCommutative)
	}
}

func (p *MonoidalLowLevel[E, T]) CanSet(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a T
		b := p.g.Draw(t, "b")
		E(&a).Set(b)
		require.Equal(t, ct.True, b.Equal(E(&a)))
	})
}

func (p *MonoidalLowLevel[E, T]) AdditionIsAssociative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c, ab, abc, bc, a_bc T
		x := p.g.Draw(t, "x")
		y := p.g.Draw(t, "y")
		z := p.g.Draw(t, "z")

		E(&a).Set(x)
		E(&b).Set(y)
		E(&c).Set(z)

		E(&ab).Add(E(&a), E(&b))
		E(&abc).Add(E(&ab), E(&c))

		E(&bc).Add(E(&b), E(&c))
		E(&a_bc).Add(E(&a), E(&bc))

		require.Equal(t, ct.True, E(&abc).Equal(E(&a_bc)))
	})
}

func (p *MonoidalLowLevel[E, T]) AdditionIsCommutative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c1, c2 T
		x := p.g.Draw(t, "x")
		y := p.g.Draw(t, "y")

		E(&a).Set(x)
		E(&b).Set(y)

		E(&c1).Add(E(&a), E(&b))
		E(&c2).Add(E(&b), E(&a))

		require.Equal(t, ct.True, E(&c1).Equal(E(&c2)))
	})
}

func (p *MonoidalLowLevel[E, T]) Double(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c T
		x := p.g.Draw(t, "x")

		E(&a).Set(x)
		E(&b).Add(E(&a), E(&a))
		E(&c).Double(E(&a))

		require.Equal(t, ct.True, E(&b).Equal(E(&c)))
	})
}

func (p *MonoidalLowLevel[E, T]) ZeroIsNeutralElement(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c, zero T
		x := p.g.Draw(t, "x")

		E(&a).Set(x)
		E(&zero).SetZero()

		E(&b).Add(E(&a), E(&zero))
		E(&c).Add(E(&zero), E(&a))

		require.Equal(t, ct.True, E(&a).Equal(E(&b)))
		require.Equal(t, ct.True, E(&a).Equal(E(&c)))
	})
}

func (p *MonoidalLowLevel[E, T]) ZeroIsIdentifiable(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var zero T
		E(&zero).SetZero()
		require.Equal(t, ct.True, E(&zero).IsZero())
		x := p.g.Draw(t, "x")
		require.NotEqual(t, E(x).IsZero(), E(x).IsNonZero())
	})
}

func (p *MonoidalLowLevel[E, T]) CanConditionallySelect(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c1, c2, c3 T
		x := p.g.Draw(t, "x")
		y := p.g.Draw(t, "y")
		cond := ct.Choice(rapid.IntRange(0, 1).Draw(t, "cond"))

		E(&a).Set(x)
		E(&b).Set(y)

		E(&c1).Select(cond, E(&a), E(&b))
		E(&c2).Select(cond, E(&a), E(&b))
		E(&c3).Select(cond.Not(), E(&b), E(&a))

		require.Equal(t, ct.True, E(&c1).Equal(E(&c2)))
		require.Equal(t, ct.True, E(&c1).Equal(E(&c3)))
	})
}

func (p *MonoidalLowLevel[E, T]) CanSerializeDeserialize(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b T
		x := p.g.Draw(t, "x")

		E(&a).Set(x)
		data := E(&a).Bytes()
		ok := E(&b).SetBytes(data)
		require.Equal(t, ct.True, ok)
		require.Equal(t, ct.True, E(&a).Equal(E(&b)))
	})
}

func (p *MonoidalLowLevel[E, T]) CanEquate(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var a, b, c T
		x := p.g.Draw(t, "x")
		y := p.g.Draw(t, "y")

		E(&a).Set(x)
		E(&b).Set(x)
		E(&c).Set(y)

		require.Equal(t, ct.True, E(&a).Equal(E(&b)))
		require.Equal(t, E(x).Equal(E(y)), E(&a).Equal(E(&c)))
	})
}
