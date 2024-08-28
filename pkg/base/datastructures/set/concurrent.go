package concurrentSet

import (
	"sync"

	"github.com/cronokirby/saferith"
	"iter"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ ds.ConcurrentSet[any] = (*ConcurrentSet[any])(nil)

type ConcurrentSet[E any] struct {
	v  ds.Set[E]
	mu sync.RWMutex
}

func NewConcurrentSet[E any](innerSet ds.Set[E]) *ConcurrentSet[E] {
	return &ConcurrentSet[E]{
		v:  innerSet,
		mu: sync.RWMutex{},
	}
}

func (s *ConcurrentSet[E]) Contains(e E) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Contains(e)
}

func (s *ConcurrentSet[E]) Add(e E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Add(e)
}

func (s *ConcurrentSet[E]) AddAll(es ...E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.AddAll(es...)
}

func (s *ConcurrentSet[E]) Remove(e E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Remove(e)
}

func (s *ConcurrentSet[E]) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Clear()
}

func (s *ConcurrentSet[E]) Equal(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Equal(other)
}

func (s *ConcurrentSet[_]) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Size()
}

func (s *ConcurrentSet[_]) Cardinality() *saferith.Nat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Cardinality()
}

func (s *ConcurrentSet[_]) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsEmpty()
}

func (s *ConcurrentSet[E]) Union(other ds.Set[E]) ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Union(other)
}

func (s *ConcurrentSet[E]) Intersection(other ds.Set[E]) ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Intersection(other)
}

func (s *ConcurrentSet[E]) Difference(other ds.Set[E]) ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Difference(other)
}

func (s *ConcurrentSet[E]) SymmetricDifference(other ds.Set[E]) ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.SymmetricDifference(other)
}

func (s *ConcurrentSet[E]) SubSets() []ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.SubSets()
}

func (s *ConcurrentSet[E]) IsSubSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsSubSet(other)
}

func (s *ConcurrentSet[E]) IsProperSubSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsProperSubSet(other)
}

func (s *ConcurrentSet[E]) IsSuperSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsSuperSet(other)
}

func (s *ConcurrentSet[E]) IsProperSuperSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsProperSuperSet(other)
}

func (s *ConcurrentSet[E]) IterSubSets() <-chan ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IterSubSets()
}

func (s *ConcurrentSet[E]) List() []E {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.List()
}

func (s *ConcurrentSet[E]) Clone() ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clone, ok := s.v.Clone().(*ConcurrentSet[E])
	if !ok {
		return nil
	}
	return clone
}

func (s *ConcurrentSet[E]) Iter() iter.Seq[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Iter()
}

func (s *ConcurrentSet[E]) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result, err := s.v.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal json")
	}
	return result, nil
}

func (s *ConcurrentSet[E]) Compute(e E, remappingFunction func(e E, exists bool) (E, bool)) E {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldExist := s.v.Contains(e)

	newValue, shouldStore := remappingFunction(e, oldExist)

	if shouldStore {
		s.v.Add(newValue)
	} else {
		s.v.Remove(e)
	}
	return newValue
}

func (s *ConcurrentSet[E]) ComputeIfAbsent(e E, mappingFunction func(e E) (E, bool)) E {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldExist := s.v.Contains(e)

	if oldExist {
		return e
	}

	newValue, shouldStore := mappingFunction(e)

	if shouldStore {
		s.v.Add(newValue)
	}
	return newValue
}

func (s *ConcurrentSet[E]) ComputeIfPresent(e E, remappingFunction func(e E) (E, bool)) E {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldExist := s.v.Contains(e)

	if !oldExist {
		return e
	}

	newValue, shouldStore := remappingFunction(e)

	if shouldStore {
		s.v.Add(newValue)
	} else if !shouldStore {
		s.v.Remove(e)
	}
	return newValue
}
