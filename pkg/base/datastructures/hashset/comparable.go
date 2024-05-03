package hashset

import (
	"encoding/json"

	"github.com/cronokirby/saferith"
	"golang.org/x/exp/maps"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type ComparableHashSet[E comparable] struct {
	v map[E]bool
}

func NewComparableHashSet[E comparable](xs ...E) ds.Set[E] {
	s := &ComparableHashSet[E]{
		v: make(map[E]bool),
	}
	for _, x := range xs {
		s.v[x] = true
	}
	return s
}

func (s *ComparableHashSet[E]) Contains(e E) bool {
	_, exists := s.v[e]
	return exists
}

func (s *ComparableHashSet[E]) Add(e E) {
	s.v[e] = true
}

func (s *ComparableHashSet[E]) AddAll(es ...E) {
	for _, e := range es {
		s.v[e] = true
	}
}

func (s *ComparableHashSet[E]) Remove(e E) {
	delete(s.v, e)
}

func (s *ComparableHashSet[E]) Clear() {
	clear(s.v)
}

func (s *ComparableHashSet[E]) Equal(other ds.Set[E]) bool {
	return s.SymmetricDifference(other).IsEmpty()
}

func (s *ComparableHashSet[_]) Size() int {
	return len(s.v)
}

func (s *ComparableHashSet[_]) Cardinality() *saferith.Nat {
	return new(saferith.Nat).SetUint64(uint64(s.Size()))
}

func (s *ComparableHashSet[_]) IsEmpty() bool {
	return len(s.v) == 0
}

func (s *ComparableHashSet[E]) Union(other ds.Set[E]) ds.Set[E] {
	result := s.Clone()
	result.AddAll(other.List()...)
	return result
}

func (s *ComparableHashSet[E]) Intersection(other ds.Set[E]) ds.Set[E] {
	result := NewComparableHashSet[E]()
	for k1 := range s.v {
		if other.Contains(k1) {
			result.Add(k1)
		}
	}
	return result
}

func (s *ComparableHashSet[E]) Difference(other ds.Set[E]) ds.Set[E] {
	result := s.Clone()
	for k := range s.v {
		if !other.Contains(k) {
			result.Add(k)
		}
	}
	return result
}

func (s *ComparableHashSet[E]) SymmetricDifference(other ds.Set[E]) ds.Set[E] {
	return s.Difference(other).Union(other.Difference(s))
}

func (s *ComparableHashSet[E]) SubSets() []ds.Set[E] {
	result := make([]ds.Set[E], 1<<s.Size())
	i := 0
	for subset := range s.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

func (s *ComparableHashSet[E]) IsSubSet(other ds.Set[E]) bool {
	return other.Intersection(s).Equal(s)
}

func (s *ComparableHashSet[E]) IsProperSubSet(other ds.Set[E]) bool {
	return s.IsSubSet(other) && !s.Equal(other)
}

func (s *ComparableHashSet[E]) IsSuperSet(other ds.Set[E]) bool {
	return other.IsSubSet(s)
}

func (s *ComparableHashSet[E]) IsProperSuperSet(other ds.Set[E]) bool {
	return other.IsProperSubSet(s)
}

func (s *ComparableHashSet[E]) Iter() <-chan E {
	ch := make(chan E, 1)
	go func() {
		defer close(ch)
		for k := range s.v {
			ch <- k
		}
	}()
	return ch
}

func (s *ComparableHashSet[E]) IterSubSets() <-chan ds.Set[E] {
	ch := make(chan ds.Set[E], 1)
	go func() {
		defer close(ch)
		elements := s.List()
		n := s.Size()
		totalSubSets := 1 << n

		for i := 0; i < totalSubSets; i++ {
			var subset []E
			for j := 0; j < n; j++ {
				if i&(1<<j) != 0 {
					subset = append(subset, elements[j])
				}
			}
			ch <- NewComparableHashSet(subset...)
		}
	}()
	return ch
}

func (s *ComparableHashSet[E]) List() []E {
	return maps.Keys(s.v)
}

func (s *ComparableHashSet[E]) Clone() ds.Set[E] {
	return &ComparableHashSet[E]{
		v: maps.Clone(s.v),
	}
}

func (s *ComparableHashSet[E]) MarshalJSON() ([]byte, error) {
	temp := make(map[E]bool)
	for k, v := range s.v {
		temp[k] = v
	}
	serialised, err := json.Marshal(temp)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal json")
	}
	return serialised, nil
}

func (s *ComparableHashSet[E]) UnmarshalJSON(data []byte) error {
	var temp map[E]bool
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not json marshal comparable hashset")
	}
	s.Clear()
	for k, v := range temp {
		s.v[k] = v
	}
	return nil
}
