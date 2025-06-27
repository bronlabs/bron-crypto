package hashset

import (
	"encoding/json"
	"iter"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

type Immutable[E any] struct {
	v ds.MutableSet[E]
}

func (s *Immutable[E]) Unfreeze() ds.MutableSet[E] {
	return s.v.Clone()
}

func (s *Immutable[E]) Contains(e E) bool {
	return s.v.Contains(e)
}

func (s *Immutable[E]) Iter() iter.Seq[E] {
	return s.v.Iter()
}

func (s *Immutable[E]) Iter2() iter.Seq2[int, E] {
	return s.v.Iter2()
}

func (s *Immutable[E]) Size() int {
	return s.v.Size()
}

func (s *Immutable[E]) IsEmpty() bool {
	return s.v.IsEmpty()
}

func (s *Immutable[E]) Union(other ds.Set[E]) ds.Set[E] {
	return s.v.Union(other.Unfreeze()).Freeze()
}

func (s *Immutable[E]) Intersection(other ds.Set[E]) ds.Set[E] {
	return s.v.Intersection(other.Unfreeze()).Freeze()
}
func (s *Immutable[E]) Difference(other ds.Set[E]) ds.Set[E] {
	return s.v.Difference(other.Unfreeze()).Freeze()
}
func (s *Immutable[E]) SymmetricDifference(other ds.Set[E]) ds.Set[E] {
	return s.v.SymmetricDifference(other.Unfreeze()).Freeze()
}
func (s *Immutable[E]) SubSets() []ds.Set[E] {
	return slices.Collect(
		iterutils.Map(slices.Values(s.v.SubSets()), func(subset ds.MutableSet[E]) ds.Set[E] {
			return subset.Freeze()
		}),
	)
}

func (s *Immutable[E]) IsSubSet(of ds.Set[E]) bool {
	for k := range s.Iter() {
		if !of.Contains(k) {
			return false
		}
	}
	return true
}

func (s *Immutable[E]) IsProperSubSet(of ds.Set[E]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

func (s *Immutable[E]) IsSuperSet(of ds.Set[E]) bool {
	for k := range of.Iter() {
		if !s.Contains(k) {
			return false
		}
	}
	return true
}

func (s *Immutable[E]) IsProperSuperSet(of ds.Set[E]) bool {
	return s.IsSuperSet(of) && !s.Equal(of)
}

func (s *Immutable[E]) IterSubSets() iter.Seq[ds.Set[E]] {
	return func(yield func(ds.Set[E]) bool) {
		for subset := range s.v.IterSubSets() {
			if !yield(subset.Freeze()) {
				return
			}
		}
	}
}

func (s *Immutable[E]) List() []E {
	return s.v.List()
}

func (s *Immutable[E]) Equal(other ds.Set[E]) bool {
	return s.v.Equal(other.Unfreeze())
}

func (s *Immutable[E]) Clone() ds.Set[E] {
	return s.v.Freeze()
}

func (s *Immutable[E]) Cardinality() int {
	return s.v.Cardinality()
}
func (s *Immutable[E]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.v)
}
