package ds_testutils

import (
	"testing"

	"pgregory.net/rapid"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/stretchr/testify/require"
)

type AbstractSetInvariants[E any, S ds.AbstractSet[E]] struct {
	MaxNumElements uint64 // Maximum number of elements in the generated sets
	Generator      func(nElements uint64) *rapid.Generator[S]
}

func NewAbstractSetInvariants[E any, S ds.AbstractSet[E]](maxNumElements uint64, generator func(nElements uint64) *rapid.Generator[S]) *AbstractSetInvariants[E, S] {
	return &AbstractSetInvariants[E, S]{
		MaxNumElements: maxNumElements,
		Generator:      generator,
	}
}

func (asi *AbstractSetInvariants[E, S]) Check(t *testing.T) {
	rapid.Check(t, asi.Cardinality)
	rapid.Check(t, asi.ContainsAndIter)
}

func (asi *AbstractSetInvariants[E, S]) Cardinality(rt *rapid.T) {
	numElements := asi.generateRandomCardinality(rt)
	A := asi.generateRandomSetN(rt, numElements)

	require.Equal(rt, numElements, A.Cardinality().Uint64(),
		"cardinality must match the number of elements in the set")
	require.Equal(rt, uint64(0), asi.generateEmptySet(rt).Cardinality().Uint64(),
		"cardinality must be 0 for an empty set")
}

func (asi *AbstractSetInvariants[E, S]) ContainsAndIter(rt *rapid.T) {
	numElements := asi.generateRandomCardinality(rt)
	A := asi.generateRandomSetN(rt, numElements)
	B := asi.generateEmptySet(rt)

	countedElements := 0
	for e := range A.Iter() {
		require.True(rt, A.Contains(e), "element %v must be in the set", e)
		countedElements++
		require.False(rt, B.Contains(e), "element %v must not be in the empty set", e)
	}
	require.Equal(rt, numElements, countedElements,
		"all elements must be in the set")
}

func (asi *AbstractSetInvariants[E, S]) generateRandomSetN(rt *rapid.T, n uint64) S {
	if n > uint64(asi.MaxNumElements) {
		require.Fail(rt, "n (%d) must be less than MaxNumElements (%d)", n, asi.MaxNumElements)
	}
	return asi.Generator(n).Draw(rt, "TestSet")
}

func (asi *AbstractSetInvariants[E, S]) generateRandomCardinality(rt *rapid.T) uint64 {
	return rapid.Uint64Range(1, uint64(asi.MaxNumElements)).Draw(rt, "numElements")
}

func (asi *AbstractSetInvariants[E, S]) generateEmptySet(rt *rapid.T) S {
	return asi.Generator(0).Draw(rt, "TestSet")
}
