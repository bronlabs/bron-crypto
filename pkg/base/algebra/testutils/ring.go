package curves_testutils

import (
	"fmt"
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
	t.Helper()

	actual := rg.Characteristic()
	mulIdentity := rg.MultiplicativeIdentity()
	expected := new(saferith.Nat).SetUint64(0)
	sum := mulIdentity
	for !sum.Equal(rg.AdditiveIdentity()) {
		sum = sum.Add(mulIdentity)
		expected = expected.Add(expected, new(saferith.Nat).SetUint64(1), -1)
	}
	require.Equal(t, expected, actual)

}
func (rgei *RigElementInvariants[R, E]) MulAdd(t *testing.T, rg algebra.Rig[R, E], rigElement1 algebra.RigElement[R, E], ringElement1, ringElement2 algebra.RingElement[R, E]) {
	t.Helper()

	actual := rigElement1.MulAdd(ringElement1, ringElement2)
	expected := rigElement1.Mul(ringElement1).Add(ringElement2)

	require.True(t, expected.Equal(actual))
}

func (fri *FiniteRingInvariants[R, E]) QuadraticResidue(t *testing.T, frg algebra.FiniteRing[R, E], p algebra.FiniteRingElement[R, E]) {
	t.Helper()
	q, err := frg.QuadraticResidue(p)
	require.NoError(t, err)

	qNat := new(saferith.Nat).SetBytes(q.Bytes())
	pNat := new(saferith.Nat).SetBytes(p.Bytes())

	qNat.Mod(qNat, frg.Order())
	pNat.Mod(pNat, frg.Order())

	require.Equal(t, qNat, pNat,
		fmt.Sprintf("qNat: %v, pNat: %v", qNat, pNat))
}

func (frei *FiniteRingElementInvariants[R, E]) Sqrt(t *testing.T, p algebra.FiniteRingElement[R, E]) {
	t.Helper()
	q, err := p.Sqrt()
	require.NoError(t, err)

	qNat := new(saferith.Nat).SetBytes(q.Bytes())
	pNat := new(saferith.Nat).SetBytes(p.Square().Bytes())

	qRemainder := qNat.Mod(qNat, p.Structure().Order())
	pRemainder := pNat.Mod(pNat, p.Structure().Order())

	require.Equal(t, qRemainder, pRemainder)
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
	rgi := &RigInvariants[R, E]{}
	t.Run("Characteristic", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		rgi.Characteristic(t, rg, element)
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
		gen1 := elementGenerator.Clone()
		gen2 := elementGenerator.Clone()
		gen3 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		isEmpty2 := gen1.Prng().IntRange(0, 16)
		isEmpty3 := gen1.Prng().IntRange(0, 16)
		element1 := gen1.Empty()
		if isEmpty1 != 0 {
			element1 = gen1.GenerateNonZero()
		}
		element2 := gen2.Empty()
		if isEmpty2 != 0 {
			element2 = gen2.GenerateNonZero()
		}
		element3 := gen3.Empty()
		if isEmpty3 != 0 {
			element3 = gen3.GenerateNonZero()
		}
		rgei.MulAdd(t, rg, element1, element2, element3)
	})
}

func CheckFiniteRingInvariants[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]](t *testing.T, rg R, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, rg)
	require.NotNil(t, elementGenerator)
	// CheckFiniteStructureInvariants[R, E](t, rg, elementGenerator)
	CheckRingInvariants[R, E](t, rg, elementGenerator)
	CheckBytesSerializationInvariants[E](t, elementGenerator)
	fri := &FiniteRingInvariants[R, E]{}
	t.Run("QuadraticResidue", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		fri.QuadraticResidue(t, rg, element)
	})
	frei := &FiniteRingElementInvariants[R, E]{}
	t.Run("Sqrt", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		frei.Sqrt(t, element)
	})
}
