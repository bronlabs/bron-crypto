package set_property_test

import (
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	tu "github.com/copperexchange/krypton-primitives/pkg/base/testutils"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const VariableSize = -1

type PropertyTestingSuite[E any] interface {
	Generator(t *rapid.T) *rapid.Generator[ds.Set[E]]
	SubSetGenerator(t *rapid.T, set ds.Set[E], size int) *rapid.Generator[ds.Set[E]]
	ElementGenerator(t *rapid.T, set ds.Set[E]) (*rapid.Generator[E], error)
	ExpectedSize(t *rapid.T) int
	IsEmpty(t *rapid.T) bool
	IsVariableSize(t *rapid.T) bool
	EmptySet(t *rapid.T) ds.Set[E]
	Draw(t *rapid.T, strs ...string) ds.Set[E]
	DrawElement(t *rapid.T, set ds.Set[E], strs ...string) (E, error)
	DrawSubSet(t *rapid.T, set ds.Set[E], size int, strs ...string) ds.Set[E]
	Iterate(t *rapid.T, iterator func() <-chan E, breakIndex int) <-chan E
	IterateSubSets(t *rapid.T, iterator func() <-chan ds.Set[E], breakIndex int) <-chan ds.Set[E]
	MaxIter() int
	MinIter() int
}

type Adapter[E any] struct {
	ElementToInt func(E) int
	IntToElement func(int) E
	SetToInts    func(ds.Set[E]) []int
	IntsToSet    func([]int) ds.Set[E]
}

type Invariants[E any] struct {
	Suite PropertyTestingSuite[E]
}

func (i *Invariants[E]) Cardinality(t *rapid.T) {
	t.Helper()
	require.NotPanics(t, func() { i.Suite.Draw(t).Cardinality() }, "cardinality should not panic")
	if !i.Suite.IsVariableSize(t) {
		require.Equal(t, i.Suite.ExpectedSize(t), int(i.Suite.Draw(t).Cardinality().Uint64()),
			"Cardinality must be equal to the number of elements in the set")
	}
}

func (i *Invariants[E]) ContainsAndIter(t *rapid.T, breakAtIter int) {
	t.Helper()
	set := i.Suite.Draw(t)
	for e := range i.Suite.Iterate(t, set.Iter, breakAtIter) {
		require.True(t, set.Contains(e), "All elements returned by Iter must be in the set (%v was not)", e)
	}
}

func (i *Invariants[E]) Union(t *rapid.T, breakAtIter int) {
	t.Helper()
	A := i.Suite.Draw(t, "A")
	B := i.Suite.Draw(t, "B")
	C := A.Union(B)

	// becasue we might not be able to finish the check if the set is large
	require.GreaterOrEqual(t, A.Size()+B.Size(), C.Size())

	for ai := range i.Suite.Iterate(t, A.Iter, breakAtIter) {
		require.True(t, C.Contains(ai), "C did not contain (%v) from A", ai)
	}

	for bi := range i.Suite.Iterate(t, B.Iter, breakAtIter) {
		require.True(t, C.Contains(bi), "C did not contain (%v) from B", bi)
	}

	for ci := range i.Suite.Iterate(t, C.Iter, breakAtIter) {
		require.True(t, A.Contains(ci) || B.Contains(ci), "union of A and B contains an element (%v) not in either", ci)
	}
}

func (i *Invariants[E]) IterSubSets(t *rapid.T, breakAtSubSetIter, breakAtElementCheckIter int) {
	t.Helper()
	set := i.Suite.Draw(t)
	for si := range i.Suite.IterateSubSets(t, set.IterSubSets, breakAtSubSetIter) {
		for ei := range i.Suite.Iterate(t, si.Iter, breakAtElementCheckIter) {
			require.True(t, set.Contains(ei), "element of the subset (%v) is not part of the given set", ei)
		}
	}
}

func (i *Invariants[E]) IsSubSet(t *rapid.T, breakAtIndex int) {
	t.Helper()
	set := i.Suite.Draw(t)
	subSet := i.Suite.DrawSubSet(t, set, -1)
	for ei := range i.Suite.Iterate(t, subSet.Iter, breakAtIndex) {
		require.True(t, set.Contains(ei), "element (%v) is not in S")
	}
}

func CheckInvariants[E any](t *testing.T, suite PropertyTestingSuite[E]) {
	t.Helper()
	inv := &Invariants[E]{
		Suite: suite,
	}
	useDefaultMaxIter := -1
	rapid.Check(t, tu.CompileInvariant(t, inv.Cardinality))
	rapid.Check(t, tu.CompileInvariant(t, inv.ContainsAndIter, useDefaultMaxIter))
	rapid.Check(t, tu.CompileInvariant(t, inv.Union, useDefaultMaxIter))
	rapid.Check(t, tu.CompileInvariant(t, inv.IterSubSets, useDefaultMaxIter, useDefaultMaxIter))
	rapid.Check(t, tu.CompileInvariant(t, inv.IsSubSet, useDefaultMaxIter))

}
