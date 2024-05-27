package curves_testutils

import (
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	// test_utils "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type StructuredSetInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]] struct{}

type StructuredSetElementInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]] struct{}

type FiniteStructureInvariants[G algebra.FiniteStructure[G, GE], GE algebra.StructuredSetElement[G, GE]] struct{}

type PointedSetInvariants[G algebra.PointedSet[G, GE], GE algebra.PointedSetElement[G, GE]] struct{}

type PointedSetElementInvariants[G algebra.PointedSet[G, GE], GE algebra.PointedSetElement[G, GE]] struct{}

func (ssi *StructuredSetInvariants[G, GE]) Random(t *testing.T, structuredSet algebra.StructuredSet[G, GE], prng io.Reader) {
	t.Helper()

	el1, err := structuredSet.Random(prng)
	require.NoError(t, err)
	require.True(t, structuredSet.Contains(el1),
		"Random set element must be always contained in the set.")

	el2, err := structuredSet.Random(prng)
	require.NoError(t, err)
	require.True(t, structuredSet.Contains(el2),
		"Random set element must be always contained in the set.")
}

func (ssi *StructuredSetInvariants[G, GE]) Element(t *testing.T, structuredSet algebra.StructuredSet[G, GE]) {
	t.Helper()

	require.True(t, structuredSet.Contains(structuredSet.Element()),
		"Element must be always contained in the set.")
}

func (ssi *StructuredSetInvariants[G, GE]) Name(t *testing.T, structuredSet algebra.StructuredSet[G, GE]) {
	t.Helper()

	require.NotEmpty(t, structuredSet.Name(), "Name must not be empty.")
	require.Equal(t, structuredSet.Name(), structuredSet.Name(), "Name must be deterministic.")
}

func (ssi *StructuredSetInvariants[G, GE]) Order(t *testing.T, structuredSet algebra.StructuredSet[G, GE]) {
	t.Helper()

	order := structuredSet.Order()
	count := 0
	iterator := structuredSet.Iterator()
	for iterator.HasNext() {
		count++
	}
	saferith.ModulusFromUint64(uint64(count))
	require.Equal(t, order, count)
}

func (ssi *StructuredSetInvariants[G, GE]) Unwrap(t *testing.T, structuredSet algebra.StructuredSet[G, GE]) {
	t.Helper()

	unWarpped := structuredSet.Unwrap()
	require.IsType(t, structuredSet, unWarpped)
}

func (ssei *StructuredSetElementInvariants[G, GE]) Unwrap(t *testing.T, structuredSet algebra.StructuredSet[G, GE], structuredSetElement algebra.StructuredSetElement[G, GE], prng io.Reader) {
	t.Helper()

	el, _ := structuredSet.Random(prng)
	element := el.Unwrap()
	require.IsType(t, structuredSetElement, element)
	require.True(t, element.Equal(el))
}

func (ssei *StructuredSetElementInvariants[G, GE]) Clone(t *testing.T, structuredSet algebra.StructuredSet[G, GE], prng io.Reader) {
	t.Helper()

	el, _ := structuredSet.Random(prng)
	elemet := el.Clone()

	require.True(t, elemet.Equal(el))
}

func (fsi *FiniteStructureInvariants[G, GE]) Hash(t *testing.T, finiteStructure algebra.FiniteStructure[G, GE], prng io.Reader) {
	t.Helper()

	el, err := finiteStructure.Hash([]byte("test"))
	if err != nil {
		require.False(t, finiteStructure.Contains(el),
			"Set should not contain the element")
	} else {
		require.True(t, finiteStructure.Contains(el),
			"Set should contain the element")
	}
}

func (psi *PointedSetElementInvariants[G, GE]) IsBasePoint(t *testing.T, pointedSet algebra.PointedSet[G, GE]) {
	t.Helper()
	// TODO: IsBasePoint is not Implement for the curve
	// expectedPoint := pointedSet.BasePoint()
	// require.True(t, expectedPoint.IsBasePoint())
}

func CheckStructuredSetInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, structuredSet G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()

	// test_utils.CheckSetInvariants[G, GE](t, structuredSet) // TODO: Missing Add method
	ssi := &StructuredSetInvariants[G, GE]{}
	prng := fu.NewPrng()
	// ssi.Random(t, structuredSet, prng)
	// ssi.Element(t, structuredSet)
	// ssi.Order(t, structuredSet) // TODO: need to implement iter for curves
	ssi.Unwrap(t, structuredSet)

	ssei := &StructuredSetElementInvariants[G, GE]{}
	t.Run("Unwarp", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		ssei.Unwrap(t, structuredSet, element, prng)
	})
	ssei.Clone(t, structuredSet, prng)
}

func CheckStructuredSetConstant[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, structuredSet G, elementGenerator fu.ObjectGenerator[GE]) {
	// test_utils.CheckSetInvariants[G, GE](t, structuredSet) // TODO: Missing Add method
	ssi := &StructuredSetInvariants[G, GE]{}
	ssi.Element(t, structuredSet)
	ssi.Name(t, structuredSet)
	ssi.Unwrap(t, structuredSet)
}
func CheckFiniteStructureInvariants[G algebra.FiniteStructure[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, finiteStructure G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()

	CheckStructuredSetInvariants[G, GE](t, finiteStructure, elementGenerator)
	prng := fu.NewPrng()
	fsi := &FiniteStructureInvariants[G, GE]{}
	fsi.Hash(t, finiteStructure, prng)
}

func CheckPointedSetElementConstant[G algebra.PointedSet[G, GE], GE algebra.PointedSetElement[G, GE]](t *testing.T, pointedSet G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	// TODO: Implement IsBasePoint for the curve
	CheckStructuredSetInvariants[G, GE](t, pointedSet, elementGenerator)
	psei := &PointedSetElementInvariants[G, GE]{}
	psei.IsBasePoint(t, pointedSet)
}
