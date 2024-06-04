package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/cronokirby/saferith"
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
	// TODO: Check the logic
	t.Helper()
	order := rg.Order().Nat()
	mulIdentity := rg.MultiplicativeIdentity()

	sum := mulIdentity
	for range order.Big().Uint64() {
		sum = sum.Add(mulIdentity)
	}
	require.True(t, sum.Equal(rg.AdditiveIdentity()))
}
func (rgei *RigElementInvariants[R, E]) MulAdd(t *testing.T, rg algebra.Rig[R, E], rigElement1 algebra.RigElement[R, E], ringElement1, ringElement2 algebra.RingElement[R, E]) {
	t.Helper()

	actual := rigElement1.MulAdd(ringElement1, ringElement2)
	expected := rigElement1.Mul(ringElement1).Add(ringElement2)

	require.True(t, expected.Equal(actual))
}

func (fri *FiniteRingInvariants[R, E]) QuadraticResidue(t *testing.T, frg algebra.FiniteRing[R, E], p algebra.FiniteRingElement[R, E]) {
	t.Helper()

	// q   = p^2 (mod S.Order())
	pTwoNat := new(saferith.Nat).SetBytes(p.Square().Bytes())
	pTwoNatClone := pTwoNat.Clone()
	expectedQ := pTwoNatClone.Mod(pTwoNatClone, frg.Order())

	// p^2 = q  (mod S.Order())
	q, err := frg.QuadraticResidue(p)
	require.NoError(t, err)

	qNat := new(saferith.Nat).SetBytes(q.Bytes())
	qNatClone := qNat.Clone()
	expectedPSquared := qNatClone.Mod(qNatClone, frg.Order())
	require.True(t, expectedPSquared.Eq(pTwoNat) == 1, "expected p^2 = q  (mod S.Order())")
	require.True(t, expectedQ.Eq(qNat) == 1, "expected q   = p^2 (mod S.Order())")
}

func (frei *FiniteRingElementInvariants[R, E]) Sqrt(t *testing.T, p algebra.FiniteRingElement[R, E]) {
	t.Helper()
	// TODO: QuadraticResidue
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
	// Characteristic
}

func CheckRingInvariants[R algebra.Ring[R, E], E algebra.RingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	CheckRigInvariants[R, E](t, rg, elementGenerator)
	// CheckAdditiveGroupInvariants[R, E](t, rg, elementGenerator) // TODO: IsTorsionElementUnderAddition not implemented for Scalar

	rgei := &RigElementInvariants[R, E]{}
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	t.Run("MulAdd", func(t *testing.T) {
		t.Parallel()
		rgei.MulAdd(t, rg, gen.Generate(), gen.Generate(), gen.Generate())
	})
}

func CheckFiniteRingInvariants[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	// CheckFiniteStructureInvariants[R, E](t, rg, elementGenerator) // TODO: Contains not implemented for Scalar
	// CheckRingInvariants[R, E](t, rg, elementGenerator) // TODO: IsTorsionElementUnderAddition not implemented for Scalar
	CheckBytesSerializationInvariants[E](t, elementGenerator)
	// QuadraticResidue // TODO: check the logic
	// Sqrt // TODO: check the logic
}
