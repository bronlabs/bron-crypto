package hashset

import (
	"encoding/json"
	"fmt"
	"hash/fnv"

	"golang.org/x/exp/maps"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ ds.HashSet[int] = (ComparableHashSet[int])(nil)

type ComparableHashSet[E comparable] map[E]bool

func NewComparableHashSet[E comparable](xs ...E) ComparableHashSet[E] {
	s := make(ComparableHashSet[E])
	for _, x := range xs {
		s[x] = true
	}
	return s
}

func (s ComparableHashSet[E]) Contains(e E) bool {
	_, exists := s[e]
	return exists
}

func (s ComparableHashSet[E]) Add(e E) {
	s[e] = true
}

func (s ComparableHashSet[E]) Merge(es ...E) {
	for _, e := range es {
		s.Add(e)
	}
}

func (s ComparableHashSet[E]) Remove(e E) {
	delete(s, e)
}

func (s ComparableHashSet[E]) Clear() {
	maps.Clear(s)
}

func (s ComparableHashSet[E]) Equal(other ds.HashSet[E]) bool {
	return s.SymmetricDifference(other).IsEmpty()
}

func (s ComparableHashSet[_]) Size() int {
	return len(s)
}

func (s ComparableHashSet[_]) IsEmpty() bool {
	return s.Size() == 0
}

func (s ComparableHashSet[E]) Union(other ds.HashSet[E]) ds.HashSet[E] {
	result := s.Clone()
	result.Merge(other.List()...)
	return result
}

func (s ComparableHashSet[E]) Intersection(other ds.HashSet[E]) ds.HashSet[E] {
	result := NewComparableHashSet[E]()
	for k1 := range s {
		if other.Contains(k1) {
			result.Add(k1)
		}
	}
	return result
}

func (s ComparableHashSet[E]) Difference(other ds.HashSet[E]) ds.HashSet[E] {
	result := s.Clone()
	for k := range s {
		if !other.Contains(k) {
			result.Add(k)
		}
	}
	return result
}

func (s ComparableHashSet[E]) SymmetricDifference(other ds.HashSet[E]) ds.HashSet[E] {
	return s.Difference(other).Union(other.Difference(s))
}

func (s ComparableHashSet[E]) SubSets() []ds.HashSet[E] {
	result := make([]ds.HashSet[E], 1<<s.Size())
	i := 0
	for subset := range s.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

func (s ComparableHashSet[E]) IsSubSet(other ds.HashSet[E]) bool {
	return other.Intersection(s).Equal(s)
}

func (s ComparableHashSet[E]) IsProperSubSet(other ds.HashSet[E]) bool {
	return s.IsSubSet(other) && !s.Equal(other)
}

func (s ComparableHashSet[E]) IsSuperSet(other ds.HashSet[E]) bool {
	return other.IsSubSet(s)
}

func (s ComparableHashSet[E]) IsProperSuperSet(other ds.HashSet[E]) bool {
	return other.IsProperSubSet(s)
}

func (s ComparableHashSet[E]) Iter() <-chan E {
	ch := make(chan E, 1)
	for k := range s {
		ch <- k
	}
	return ch
}

func (s ComparableHashSet[E]) IterSubSets() <-chan ds.HashSet[E] {
	ch := make(chan ds.HashSet[E], 1)
	go func() {
		defer close(ch)
		elements := s.List()
		n := s.Size()
		totalSubSets := 1 << n

		for i := 0; i < totalSubSets; i++ {
			var subset []E
			for j := 0; j < n; j++ {
				if i&(1<<j) != 0 {
					subset = append(subset, elements[i])
				}
			}
			ch <- NewComparableHashSet(subset...)
		}
	}()
	return ch
}

func (s ComparableHashSet[E]) List() []E {
	return maps.Keys(s)
}

func (s ComparableHashSet[E]) Clone() ds.HashSet[E] {
	return maps.Clone(s)
}

func (s ComparableHashSet[E]) HashCode() uint64 {
	h := fnv.New64a()
	for e := range s.Iter() {
		fmt.Fprintf(h, "%v", e)
	}
	return h.Sum64()
}

func (s ComparableHashSet[E]) MarshalJSON() ([]byte, error) {
	temp := make(map[E]bool)
	for k, v := range s {
		temp[k] = v
	}
	serialised, err := json.Marshal(temp)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal json")
	}
	return serialised, nil
}

func (s ComparableHashSet[E]) UnmarshalJSON(data []byte) error {
	var temp map[E]bool
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not json marshal comparable hashset")
	}
	s.Clear()
	for k, v := range temp {
		s[k] = v
	}
	return nil
}
