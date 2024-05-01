package set_property_test

import (
	"strings"
	"testing"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	dstu "github.com/copperexchange/krypton-primitives/pkg/base/datastructures/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"pgregory.net/rapid"
)

var _ PropertyTestingSuite[int] = (*SetDataStructureSuite[int])(nil)

type SetDataStructureSuite[E any] struct {
	generator      *rapid.Generator[ds.Set[E]]
	size           int
	setConstructor func(xs ...E) ds.Set[E]

	Adapter[E]
}

func (s *SetDataStructureSuite[E]) Generator(t *rapid.T) *rapid.Generator[ds.Set[E]] {
	t.Helper()
	return s.generator
}

func (s *SetDataStructureSuite[E]) ElementGenerator(t *rapid.T, set ds.Set[E]) (*rapid.Generator[E], error) {
	t.Helper()
	if set.IsEmpty() {
		return nil, errs.NewSize("size of set is zero")
	}
	t.Helper()
	return rapid.Map(
		rapid.SampledFrom(s.SetToInts(set)),
		s.IntToElement,
	), nil
}

func (s *SetDataStructureSuite[E]) SubSetGenerator(t *rapid.T, set ds.Set[E], size int) *rapid.Generator[ds.Set[E]] {
	t.Helper()
	if set.IsEmpty() {
		return rapid.Just(s.EmptySet(t))
	}
	minLen := 0
	maxLen := set.Size()
	switch {
	case size < 0:
		minLen = 0
		maxLen = set.Size()
	case size == 0:
		return rapid.Just(s.EmptySet(t))
	case size >= set.Size():
		return rapid.Just(set)
	default:
		minLen = size
		maxLen = size
	}
	return rapid.Map(
		rapid.SliceOfNDistinct(rapid.SampledFrom(s.SetToInts(set)), minLen, maxLen, rapid.ID),
		s.IntsToSet,
	)
}

func (s *SetDataStructureSuite[E]) ExpectedSize(t *rapid.T) int {
	t.Helper()
	return s.size
}

func (s *SetDataStructureSuite[E]) IsEmpty(t *rapid.T) bool {
	t.Helper()
	return s.size == 0
}

func (s *SetDataStructureSuite[E]) IsVariableSize(t *rapid.T) bool {
	t.Helper()
	return s.size == VariableSize
}

func (s *SetDataStructureSuite[E]) EmptySet(t *rapid.T) ds.Set[E] {
	t.Helper()
	return s.setConstructor()
}

func (s *SetDataStructureSuite[E]) Draw(t *rapid.T, strs ...string) ds.Set[E] {
	if len(strs) == 0 {
		strs = append(strs, "Set")
	}
	return s.generator.Draw(t, strings.Join(strs, "_"))
}

func (s *SetDataStructureSuite[E]) DrawElement(t *rapid.T, set ds.Set[E], strs ...string) (E, error) {
	if len(strs) == 0 {
		strs = append(strs, "Element")
	}
	gen, err := s.ElementGenerator(t, set)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not produce an element generator from the set")
	}
	return gen.Draw(t, strings.Join(strs, "_")), nil
}

func (s *SetDataStructureSuite[E]) DrawSubSet(t *rapid.T, set ds.Set[E], size int, strs ...string) ds.Set[E] {
	if len(strs) == 0 {
		strs = append(strs, "SubSet")
	}
	return s.SubSetGenerator(t, set, size).Draw(t, strings.Join(strs, "_"))
}

func (s *SetDataStructureSuite[E]) Iterate(t *rapid.T, iterator func() <-chan E, overrideBreakIterAt int) <-chan E {
	effectiveBreakIter := s.MaxIter()
	if overrideBreakIterAt >= 0 {
		effectiveBreakIter = overrideBreakIterAt
	}
	out := make(chan E, 1)
	go func() {
		defer close(out)
		i := 0
		for e := range iterator() {
			if i >= effectiveBreakIter {
				return
			}
			out <- e
			i++
		}
	}()
	return out
}

func (s *SetDataStructureSuite[E]) IterateSubSets(t *rapid.T, iterator func() <-chan ds.Set[E], overrideBreakIterAt int) <-chan ds.Set[E] {
	effectiveBreakIter := s.MaxIter()
	if overrideBreakIterAt >= 0 {
		effectiveBreakIter = overrideBreakIterAt
	}
	out := make(chan ds.Set[E], 1)
	go func() {
		defer close(out)
		i := 0
		for e := range iterator() {
			if i >= effectiveBreakIter {
				return
			}
			out <- e
			i++
		}
	}()
	return out
}

func (s *SetDataStructureSuite[E]) MaxIter() int {
	return 100
}

func (s *SetDataStructureSuite[E]) MinIter() int {
	return 20
}

func NewPropertyTestingSuite[E any](t *testing.T, nElements int, setConstructor func(xs ...E) ds.Set[E], adapter *Adapter[E]) *SetDataStructureSuite[E] {
	t.Helper()
	var minLen int
	var maxLen int
	var size int
	switch {
	case nElements < 0:
		minLen = 0
		maxLen = dstu.MaxNumElements
		size = VariableSize
	case nElements == 0:
		minLen = 0
		maxLen = 0
		size = 0
	case nElements > 0:
		minLen = nElements
		maxLen = nElements
		size = nElements
	}
	baseGenerator := rapid.Int()
	return &SetDataStructureSuite[E]{
		generator: rapid.Map(
			rapid.SliceOfNDistinct(baseGenerator, minLen, maxLen, rapid.ID),
			func(xs []int) ds.Set[E] {
				set := setConstructor()
				for _, x := range xs {
					set.Add(adapter.IntToElement(x))
				}
				return set
			},
		),
		setConstructor: setConstructor,
		size:           size,
		Adapter:        *adapter,
	}
}
