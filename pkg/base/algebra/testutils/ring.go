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

func (ri *RigInvariants[R, E]) Characteristic(t *testing.T, rg algebra.Rig[R, E], rgElement algebra.RigElement[R, E]) {
	t.Helper()
	// TODO: check the logic
	order := rg.Order().Nat().Bytes()
	orderBitLen := bitstring.PackedBits.BitLen(order)

	var f func(res, P algebra.RigElement[R, E], d int) algebra.RigElement[R, E]
	f = func(res, P algebra.RigElement[R, E], d int) algebra.RigElement[R, E] {
		if d == 0 {
			return rg.AdditiveIdentity()
		} else if d == 1 {
			return P
		} else if d%2 == 1 {
			return rg.Add(P, f(res, P, d-1))
		} else {
			return f(rg.Mul(P, P), P, d/2)
		}
	}
	P := rg.MultiplicativeIdentity()
	res := f(rg.AdditiveIdentity(), P, orderBitLen)
	require.True(t, res.Equal(rg.AdditiveIdentity()))
}
func (rgei *RigElementInvariants[R, E]) MulAdd(t *testing.T, rg algebra.Rig[R, E], rigElement1 algebra.RigElement[R, E], ringElement2, ringElement3 algebra.RingElement[R, E]) {
	t.Helper()

	actual := rigElement1.MulAdd(ringElement2, ringElement3)
	expected := rigElement1.Mul(ringElement2).Add(ringElement3)

	require.True(t, expected.Equal(actual))
}

func (fri *FiniteRingInvariants[R, E]) QuadraticResidue(t *testing.T, frg algebra.FiniteRing[R, E], q algebra.FiniteRingElement[R, E]) {
	t.Helper()
	// TODO: check the logic
	p, err := frg.QuadraticResidue(q)
	require.NoError(t, err)

	require.True(t, p.Square().Equal(q.Unwrap()), "expected p^2 = q  (mod S.Order())")
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
	// rig := RigInvariants[R, E]{}
	// gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero
	// t.Run("Characteristic", func(t *testing.T) {
	// 	t.Parallel()
	// 	rig.Characteristic(t, rg, gen.Generate())
	// })
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
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero
	fri := &FiniteRingInvariants[R, E]{}
	t.Run("quad", func(t *testing.T) {
		t.Parallel()
		fri.QuadraticResidue(t, rg, gen.Generate())

	})
	// QuadraticResidue // TODO: check the logic
	// Sqrt // TODO: check the logic
}
