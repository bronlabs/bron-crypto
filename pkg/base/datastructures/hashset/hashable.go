package hashset

import (
	"encoding/json"
	"iter"

	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type HashableHashSet[E ds.Hashable[E]] struct {
	v ds.Map[E, bool]
}

func NewHashableHashSet[E ds.Hashable[E]](xs ...E) ds.Set[E] {
	m := hashmap.NewHashableHashMap[E, bool]()
	for _, x := range xs {
		m.Put(x, true)
	}
	return &HashableHashSet[E]{
		v: m,
	}
}

func (s *HashableHashSet[E]) Contains(e E) bool {
	return s.v.ContainsKey(e)
}

func (s *HashableHashSet[E]) Add(e E) {
	s.v.Put(e, true)
}

func (s *HashableHashSet[E]) AddAll(es ...E) {
	for _, e := range es {
		s.v.Put(e, true)
	}
}

func (s *HashableHashSet[E]) Remove(e E) {
	s.v.Remove(e)
}

func (s *HashableHashSet[E]) Clear() {
	s.v.Clear()
}

func (s *HashableHashSet[E]) Equal(other ds.Set[E]) bool {
	return s.SymmetricDifference(other).IsEmpty()
}

func (s *HashableHashSet[_]) Size() int {
	return s.v.Size()
}

func (s *HashableHashSet[_]) Cardinality() *saferith.Nat {
	return new(saferith.Nat).SetUint64(uint64(s.v.Size()))
}

func (s *HashableHashSet[_]) IsEmpty() bool {
	return s.Size() == 0
}

func (s *HashableHashSet[E]) Union(other ds.Set[E]) ds.Set[E] {
	result := s.Clone()
	result.AddAll(other.List()...)
	return result
}

func (s *HashableHashSet[E]) Intersection(other ds.Set[E]) ds.Set[E] {
	result := NewHashableHashSet[E]()

	for element := range s.Iter() {
		if other.Contains(element) {
			result.Add(element)
		}
	}

	return result
}

func (s *HashableHashSet[E]) Difference(other ds.Set[E]) ds.Set[E] {
	result := NewHashableHashSet[E]()

	for element := range s.Iter() {
		if !other.Contains(element) {
			result.Add(element)
		}
	}
	return result
}

func (s *HashableHashSet[E]) SymmetricDifference(other ds.Set[E]) ds.Set[E] {
	return s.Difference(other).Union(other.Difference(s))
}

func (s *HashableHashSet[E]) SubSets() []ds.Set[E] {
	result := make([]ds.Set[E], 1<<s.Size())
	i := 0
	for subset := range s.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

func (s *HashableHashSet[E]) IsSubSet(other ds.Set[E]) bool {
	return other.Intersection(s).Equal(s)
}

func (s *HashableHashSet[E]) IsProperSubSet(other ds.Set[E]) bool {
	return s.IsSubSet(other) && !s.Equal(other)
}

func (s *HashableHashSet[E]) IsSuperSet(other ds.Set[E]) bool {
	return other.IsSubSet(s)
}

func (s *HashableHashSet[E]) IsProperSuperSet(other ds.Set[E]) bool {
	return other.IsProperSubSet(s)
}

func (s *HashableHashSet[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		for el := range s.v.Iter() {
			if !yield(el) {
				return
			}
		}
	}
}

func (s *HashableHashSet[E]) IterSubSets() <-chan ds.Set[E] {
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
			ch <- NewHashableHashSet(subset...)
		}
	}()
	return ch
}

func (s *HashableHashSet[E]) List() []E {
	results := make([]E, s.Size())
	i := 0

	for k := range s.Iter() {
		results[i] = k
		i++
	}

	return results
}

func (s *HashableHashSet[E]) Clone() ds.Set[E] {
	return NewHashableHashSet(s.List()...)
}

func (s *HashableHashSet[E]) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal(s.v)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}

func (s *HashableHashSet[E]) UnmarshalJSON(data []byte) error {
	result := HashableHashSet[E]{}
	if err := json.Unmarshal(data, result.v); err != nil {
		return errs.WrapSerialisation(err, "couldn't unmarshal hashable hash set")
	}
	s.Clear()

	for x := range s.Iter() {
		s.Add(x)
	}

	return nil
}
