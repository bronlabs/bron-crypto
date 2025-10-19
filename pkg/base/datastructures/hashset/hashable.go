package hashset

import (
	"encoding/json"
	"iter"

	base "github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func NewHashable[E base.Hashable[E]](xs ...E) ds.MutableSet[E] {
	s := &MutableHashable[E]{v: hashmap.NewHashable[E, struct{}]()}
	for _, x := range xs {
		s.v.Put(x, struct{}{})
	}
	return s
}

type MutableHashable[E base.Hashable[E]] struct {
	v ds.MutableMap[E, struct{}]
}

func (s *MutableHashable[E]) Add(e E) {
	s.v.Put(e, struct{}{})
}

func (s *MutableHashable[E]) AddAll(es ...E) {
	for _, e := range es {
		s.v.Put(e, struct{}{})
	}
}

func (s *MutableHashable[E]) Remove(e E) {
	s.v.Remove(e)
}

func (s *MutableHashable[E]) RemoveAll(es ...E) {
	for _, e := range es {
		s.v.Remove(e)
	}
}

func (s *MutableHashable[E]) Freeze() ds.Set[E] {
	return &Immutable[E]{v: &MutableHashable[E]{v: s.v.Clone()}}
}

func (s *MutableHashable[E]) Clone() ds.MutableSet[E] {
	return &MutableHashable[E]{v: s.v.Clone()}
}

func (s *MutableHashable[E]) Clear() {
	s.v.Clear()
}

func (s *MutableHashable[E]) Contains(e E) bool {
	return s.v.ContainsKey(e)
}

func (s *MutableHashable[E]) Equal(other ds.MutableSet[E]) bool {
	return s.IsSubSet(other) && other.IsSubSet(s)
}

func (s *MutableHashable[_]) Size() int {
	return s.v.Size()
}

func (s *MutableHashable[_]) Cardinality() int {
	return s.v.Size()
}

func (s *MutableHashable[_]) IsEmpty() bool {
	return s.Size() == 0
}

func (s *MutableHashable[E]) Union(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := s.Clone()
	out.AddAll(other.List()...)
	return out
}

func (s *MutableHashable[E]) Intersection(other ds.MutableSet[E]) ds.MutableSet[E] {
	mapping := hashmap.NewHashable[E, struct{}]()
	for k := range s.v.Iter() {
		if other.Contains(k) {
			mapping.Put(k, struct{}{})
		}
	}
	return &MutableHashable[E]{v: mapping}
}

func (t *MutableHashable[E]) Difference(other ds.MutableSet[E]) ds.MutableSet[E] {
	out := t.Clone()
	out.RemoveAll(other.List()...)
	return out
}

func (t *MutableHashable[E]) SymmetricDifference(other ds.MutableSet[E]) ds.MutableSet[E] {
	return t.Union(other).Difference(t.Intersection(other))
}

func (t *MutableHashable[E]) SubSets() []ds.MutableSet[E] {
	result := make([]ds.MutableSet[E], 1<<t.Size())
	i := 0
	for subset := range t.IterSubSets() {
		result[i] = subset
		i++
	}
	return result
}

func (s *MutableHashable[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		for el := range s.v.Iter() {
			if !yield(el) {
				return
			}
		}
	}
}

func (s *MutableHashable[E]) Iter2() iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		i := 0
		for el := range s.v.Iter() {
			if !yield(i, el) {
				return
			}
			i++
		}
	}
}

func (s *MutableHashable[E]) IsSubSet(of ds.MutableSet[E]) bool {
	for k := range s.Iter() {
		if !of.Contains(k) {
			return false
		}
	}
	return true
}

func (s *MutableHashable[E]) IsProperSubSet(of ds.MutableSet[E]) bool {
	return s.IsSubSet(of) && !s.Equal(of)
}

func (s *MutableHashable[E]) IsSuperSet(of ds.MutableSet[E]) bool {
	for k := range of.Iter() {
		if _, exists := s.v.Get(k); !exists {
			return false
		}
	}
	return true
}

func (s *MutableHashable[E]) IsProperSuperSet(of ds.MutableSet[E]) bool {
	return s.IsSuperSet(of) && !s.Equal(of)
}

func (s *MutableHashable[E]) IterSubSets() iter.Seq[ds.MutableSet[E]] {
	return func(yield func(ds.MutableSet[E]) bool) {
		list := s.List()
		for i := range s.Size() {
			for comb := range sliceutils.Combinations(list, uint(i)) {
				subset := NewHashable(comb...)
				if !yield(subset) {
					return
				}
			}
		}
	}
}

func (s *MutableHashable[E]) List() []E {
	return s.v.Keys()
}

func (s *MutableHashable[E]) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(s.v)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal hashset")
	}
	return data, nil
}

func (s *MutableHashable[E]) HashCode() base.HashCode {
	if s.IsEmpty() {
		return base.HashCode(0)
	}
	l := s.List()
	if len(l) == 1 {
		return l[0].HashCode()
	}
	return sliceutils.Reduce(
		sliceutils.Map(l[1:], func(e E) base.HashCode { return e.HashCode() }),
		l[0].HashCode(),
		func(a, b base.HashCode) base.HashCode { return a ^ b }, // must be commutative
	)
}
