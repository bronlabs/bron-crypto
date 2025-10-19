package hashset

import (
	"encoding/json"
	"iter"

	"golang.org/x/exp/maps"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type comparableMapping[K comparable] = map[K]struct{}

func NewComparable[E comparable](xs ...E) ds.MutableSet[E] {
	s := &MutableComparable[E]{v: make(comparableMapping[E])}
	for _, x := range xs {
		s.v[x] = struct{}{}
	}
	return s
}

type MutableComparable[E comparable] struct {
	v comparableMapping[E]
}

func (s *MutableComparable[E]) Add(e E) {
	s.v[e] = struct{}{}
}

func (s *MutableComparable[E]) AddAll(es ...E) {
	for _, e := range es {
		s.v[e] = struct{}{}
	}
}

func (s *MutableComparable[E]) Remove(e E) {
	delete(s.v, e)
}

func (s *MutableComparable[E]) RemoveAll(es ...E) {
	for _, e := range es {
		delete(s.v, e)
	}
}

func (s *MutableComparable[E]) Freeze() ds.Set[E] {
	return &Immutable[E]{v: &MutableComparable[E]{v: maps.Clone(s.v)}}
}

func (s *MutableComparable[E]) Clear() {
	maps.Clear(s.v)
}

func (s *MutableComparable[E]) Contains(e E) bool {
	_, exists := s.v[e]
	return exists
}

func (s *MutableComparable[E]) Clone() ds.MutableSet[E] {
	return &MutableComparable[E]{v: maps.Clone(s.v)}
}

func (t *MutableComparable[E]) Equal(other ds.MutableSet[E]) bool {
	return t.IsSubSet(other) && other.IsSubSet(t)
}

func (t *MutableComparable[_]) Size() int {
	return len(t.v)
}

func (t *MutableComparable[_]) Cardinality() int {
	return len(t.v)
}

func (t *MutableComparable[_]) IsEmpty() bool {
	return len(t.v) == 0
}

func (t *MutableComparable[E]) Union(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := t.Clone()
	out.AddAll(other.List()...)
	return out
}

func (t *MutableComparable[E]) Intersection(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := &MutableComparable[E]{v: make(comparableMapping[E])}
	for k := range t.Iter() {
		if other.Contains(k) {
			out.v[k] = struct{}{}
		}
	}
	return out
}

func (t *MutableComparable[E]) Difference(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := t.Clone()
	out.RemoveAll(other.List()...)
	return out
}

func (t *MutableComparable[E]) SymmetricDifference(other ds.MutableSet[E]) ds.MutableSet[E] {
	return t.Union(other).Difference(t.Intersection(other))
}

func (t *MutableComparable[E]) SubSets() []ds.MutableSet[E] {
	result := make([]ds.MutableSet[E], 1<<t.Size())
	i := 0
	for subset := range t.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

func (s *MutableComparable[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		for el := range s.v {
			if !yield(el) {
				return
			}
		}
	}
}

func (s *MutableComparable[E]) Iter2() iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		i := 0
		for el := range s.v {
			if !yield(i, el) {
				return
			}
			i++
		}
	}
}

func (s *MutableComparable[E]) IsSubSet(of ds.MutableSet[E]) bool {
	for k := range s.Iter() {
		if !of.Contains(k) {
			return false
		}
	}
	return true
}

func (s *MutableComparable[E]) IsProperSubSet(of ds.MutableSet[E]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

func (s *MutableComparable[E]) IsSuperSet(of ds.MutableSet[E]) bool {
	for k := range of.Iter() {
		if _, exists := s.v[k]; !exists {
			return false
		}
	}
	return true
}

func (s *MutableComparable[E]) IsProperSuperSet(of ds.MutableSet[E]) bool {
	return s.IsSuperSet(of) && !s.Equal(of)
}

func (s *MutableComparable[E]) IterSubSets() iter.Seq[ds.MutableSet[E]] {
	return func(yield func(ds.MutableSet[E]) bool) {
		list := s.List()
		for i := range s.Size() {
			for comb := range sliceutils.Combinations(list, uint(i)) {
				subset := NewComparable(comb...)
				if !yield(subset) {
					return
				}
			}
		}
	}
}

func (s *MutableComparable[E]) List() []E {
	return maps.Keys(s.v)
}

func (s *MutableComparable[E]) MarshalJSON() ([]byte, error) {
	temp := make(map[E]struct{})
	for k := range s.v {
		temp[k] = struct{}{}
	}
	return json.Marshal(temp)
}
