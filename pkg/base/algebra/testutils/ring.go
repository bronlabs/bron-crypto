package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
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

func (ri *RigInvariants[R, E]) Characteristic(t *testing.T, rg algebra.Rig[R, E]) {
	t.Helper()

	if rg.Characteristic().EqZero() == 1 { // No characteristic
		return
	}
	expected := rg.AdditiveIdentity()

	// Operate  MultiplicativeIdentity `Characteristic` times via Double and Add
	actual := rg.AdditiveIdentity()
	doubler := rg.MultiplicativeIdentity()
	characteristicBytes := bitstring.PackedBits(rg.Characteristic().Bytes())
	for i := range characteristicBytes.BitLen() {
		if characteristicBytes.GetBE(uint(characteristicBytes.BitLen()-1-i)) != 0 {
			actual = rg.Add(actual, doubler)
		}
		doubler = rg.Add(doubler, doubler)
	}
	require.True(t, actual.Equal(expected),
		"Characteristic did not fulfill `AdditiveIdentity = MultiplicativeIdentity * Characteristic`")
}

func (rgei *RigElementInvariants[R, E]) MulAdd(t *testing.T, rg algebra.Rig[R, E], rigElement1 algebra.RigElement[R, E], ringElement2, ringElement3 algebra.RingElement[R, E]) {
	t.Helper()

	actual := rigElement1.MulAdd(ringElement2, ringElement3)
	expected := rigElement1.Mul(ringElement2).Add(ringElement3)

	require.True(t, expected.Equal(actual))
}

func (fri *FiniteRingInvariants[R, E]) QuadraticResidue(t *testing.T, frg algebra.FiniteRing[R, E], p algebra.FiniteRingElement[R, E]) {
	t.Parallel()
	q := p.Square()
	pActual, err := frg.QuadraticResidue(q)
	require.NoError(t, err)

	require.True(t, p.Equal(pActual), "expected p^2 = q  (mod S.Order())")
}

func (frei *FiniteRingElementInvariants[R, E]) Sqrt(t *testing.T, p algebra.FiniteRingElement[R, E]) {
	t.Helper()
	q := p.Square()
	pActual, err := q.Sqrt()
	require.NoError(t, err)

	require.True(t, p.Equal(pActual), "expected p^2 = q  (mod S.Order())")
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

	ri := &RigInvariants[R, E]{}
	t.Run("Characteristic", func(t *testing.T) {
		t.Parallel()
		ri.Characteristic(t, rg)
	})
}

func CheckRingInvariants[R algebra.Ring[R, E], E algebra.RingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	CheckRigInvariants[R, E](t, rg, elementGenerator)
	// CheckAdditiveGroupInvariants[R, E](t, rg, elementGenerator) // TODO: IsTorsionElementUnderAddition not implemented for Scalar

	rgei := &RigElementInvariants[R, E]{}

	t.Run("MulAdd", func(t *testing.T) {
		t.Parallel()
		rgei.MulAdd(t, rg, elementGenerator.Generate(), elementGenerator.Generate(), elementGenerator.Generate())
	})
}

func CheckFiniteRingInvariants[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	// CheckFiniteStructureInvariants[R, E](t, rg, elementGenerator) // TODO: Contains not implemented for Scalar
	// CheckRingInvariants[R, E](t, rg, elementGenerator) // TODO: IsTorsionElementUnderAddition not implemented for Scalar
	CheckBytesSerializationInvariants[E](t, elementGenerator)
	// fri := &FiniteRingInvariants[R, E]{}

	// t.Run("QuadraticResidue", func(t *testing.T) {
	// 	t.Helper()
	// 	fri.QuadraticResidue(t, rg, elementGenerator.Generate())
	// })
	// frei := &FiniteRingElementInvariants[R, E]{}
	// t.Run("Sqrt", func(t *testing.T) {
	// 	t.Helper()
	// 	frei.Sqrt(t, elementGenerator.Generate())
	// })
}
