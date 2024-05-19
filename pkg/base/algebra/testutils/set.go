package curves_testutils

import (
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type StructuredSetInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]] struct{}

type StructuredSetElementInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]] struct{}

type FiniteStructureInvariants[G algebra.FiniteStructure[G, GE], GE algebra.StructuredSetElement[G, GE]] struct{}

type PointedSetInvariants[G algebra.PointedSet[G, GE], GE algebra.PointedSetElement[G, GE]] struct{}

type PointedSetElementInvariants[G algebra.PointedSet[G, GE], GE algebra.PointedSetElement[G, GE]] struct{}

// RULES:
// 1. Use only methods that are:
//    - Inherited from parent interfaces
//    - Tested before
// 2. Write all the invariant checks in the form of either `require.[...]` or `t.Run([...])`

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
	require.IsType(t, structuredSet, unWarpped) // TODO
	for iterator := unWarpped.Iterator(); iterator.HasNext(); {
		element := iterator.Next()
		require.True(t, structuredSet.Contains(element),
			"Element must be contained in the unwrapped Set.")
	}
}

func CheckStructuredSetConstants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, structuredSet algebra.StructuredSet[G, GE]) {
	t.Helper()

	ssi := &StructuredSetInvariants[G, GE]{}
	ssi.Name(t, structuredSet)
}

func (ssei *StructuredSetElementInvariants[G, GE]) Unwrap(t *testing.T, structuredSet algebra.StructuredSet[G, GE], structuredSetElement algebra.StructuredSetElement[G, GE], prng io.Reader) {
	t.Helper()

	el, _ := structuredSet.Random(prng)
	element := el.Unwrap()
	require.IsType(t, structuredSetElement, element) // TODO
	require.Equal(t, element, el)
}

func (ssei *StructuredSetElementInvariants[G, GE]) Clone(t *testing.T, structuredSet algebra.StructuredSet[G, GE], prng io.Reader) {
	t.Helper()

	el, _ := structuredSet.Random(prng)
	elemet := el.Clone()

	require.Equal(t, elemet, el)

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

	expectedPoint := pointedSet.BasePoint()
	require.True(t, expectedPoint.IsBasePoint())
}

func CheckStructuredSetInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, structuredSet algebra.StructuredSet[G, GE], prng io.Reader) {
	t.Helper()

	ssi := &StructuredSetInvariants[G, GE]{}
	ssi.Random(t, structuredSet, prng)
	ssi.Element(t, structuredSet)
	ssi.Order(t, structuredSet)
	// Operators
	ssi.Unwrap(t, structuredSet)
}

func CheckStructuredSetElementInvariants[G algebra.StructuredSet[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, structuredSet algebra.StructuredSet[G, GE],
	structuredSetElement algebra.StructuredSetElement[G, GE], prng io.Reader) {
	t.Helper()

	ssei := &StructuredSetElementInvariants[G, GE]{}
	ssei.Unwrap(t, structuredSet, structuredSetElement, prng)
	ssei.Clone(t, structuredSet, prng)
}

func CheckFiniteStructureInvariants[G algebra.FiniteStructure[G, GE], GE algebra.StructuredSetElement[G, GE]](t *testing.T, finiteStructure algebra.FiniteStructure[G, GE], prng io.Reader) {
	t.Helper()

	fsi := &FiniteStructureInvariants[G, GE]{}
	fsi.Hash(t, finiteStructure, prng)
	//ElementSize
	//WideElementSize
}

func CheckPointedSetElementInvariants[G algebra.PointedSet[G, GE], GE algebra.PointedSetElement[G, GE]](t *testing.T, pointedSet algebra.PointedSet[G, GE]) {
	t.Helper()

	psei := &PointedSetElementInvariants[G, GE]{}
	psei.IsBasePoint(t, pointedSet)
}
