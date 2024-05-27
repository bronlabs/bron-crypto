package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type Rginvariants[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct{}

type RgElementInvariants[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct{}

type RigInvariants[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct{}

type RigElementInvariants[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct{}

type RingInvariants[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct{}

type RingElementInvariants[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct{}

type FiniteRingInvariants[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct{}

type FiniteRingElementInvariants[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct{}

func (ri *RigInvariants[R, E]) Characteristic(t *testing.T, rg algebra.Rig[R, E], rgElement algebra.RigElement[R, E]) {
	t.Helper()
	// TODO
}
func (rgei *RigElementInvariants[R, E]) MulAdd(t *testing.T, rg algebra.Rig[R, E], rgElement algebra.RigElement[R, E]) {
	t.Helper()
	// TODO
}

func (fri *FiniteRingInvariants[R, E]) QuadraticResidue(t *testing.T, frg algebra.FiniteRing[R, E], p algebra.FiniteFieldElement[R, E]) {
	t.Helper()
	// TODO
	// q, err := frg.QuadraticResidue(p)
	// require.NoError(t, err)
	// _, reminderP := p.Square().EuclideanDiv(frg.Order())
	// _, reminderQ := q.EuclideanDiv(frg.Order())

	// require.True(t, reminderP.Equal(reminderQ))
}

func (frei *FiniteRingElementInvariants[R, E]) Sqrt(t *testing.T, frg algebra.FiniteRing[R, E], frge algebra.FiniteFieldElement[R, E]) {
	t.Helper()
	// TODO
}
func CheckRgInvariants[R algebra.Rg[R, E], E algebra.RgElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	CheckAdditiveGroupoidInvariants[R, E](t, rg, elementGenerator)
	CheckMultiplicativeGroupoidInvariants[R, E](t, rg, elementGenerator)
}
func CheckRigInvariants[R algebra.Rig[R, E], E algebra.RigElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	CheckRgInvariants[R, E](t, rg, elementGenerator)
	CheckAdditiveMonoidInvariants[R, E](t, rg, elementGenerator)
	CheckMultiplicativeMonoidInvariants[R, E](t, rg, elementGenerator)
	// rgi := &RigInvariants[R, E]{}
	// rgi.Characteristic(t, rg, element)
	// rgei := &RigElementInvariants[R, E]{}
	// rgei.MulAdd(t, rg, element)
}

func CheckRingInvariants[R algebra.Ring[R, E], E algebra.RingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	CheckRingInvariants[R, E](t, rg, elementGenerator)
	CheckAdditiveGroupInvariants[R, E](t, rg, elementGenerator)
}

func CheckFiniteRingInvariants[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	CheckFiniteStructureInvariants[R, E](t, rg, elementGenerator)
	CheckRingInvariants[R, E](t, rg, elementGenerator)
	// fri := &FiniteRingInvariants[R, E]{}
	// fri.QuadraticResidue(t, rg, elemet)
	// frei := &FiniteRingElementInvariants[R, E]{}
	// frei.Sqrt(t, rg, elemet)
}
