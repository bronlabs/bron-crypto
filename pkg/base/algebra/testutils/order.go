package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type OrderTheoreticLatticeElementInvariants[L algebra.OrderTheoreticLattice[L, LE], LE algebra.OrderTheoreticLatticeElement[L, LE]] struct{}

func (otlei *OrderTheoreticLatticeElementInvariants[L, LE]) Cmp(t *testing.T, element1, element2 algebra.OrderTheoreticLatticeElement[L, LE], expected algebra.Ordering) {
	t.Helper()

	require.Equal(t, expected, element1.Cmp(element2))

	c1 := element1.Cmp(element2)
	c2 := element2.Cmp(element1)

	require.Equal(t, c1, -c2)
}

func CheckOrderTheoreticLatticeInvariants[L algebra.OrderTheoreticLattice[L, LE], LE algebra.OrderTheoreticLatticeElement[L, LE]](t *testing.T, structure L, elementGenerator fu.ObjectGenerator[LE]) {
	t.Helper()
	require.NotNil(t, structure)
	require.NotNil(t, elementGenerator)
	CheckStructuredSetInvariants[L, LE](t, structure, elementGenerator)

	otlei := &OrderTheoreticLatticeElementInvariants[L, LE]{}
	t.Run("Equal", func(t *testing.T) {
		t.Parallel()
		el1 := elementGenerator.Generate()
		otlei.Cmp(t, el1, el1, algebra.Equal)
	})
}
