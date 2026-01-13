package hashset

import (
	"iter"
	"sync"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// ConcurrentSet is a thread-safe wrapper around a MutableSet.
// All operations are protected by a read-write mutex.
type ConcurrentSet[E any] struct {
	v  ds.MutableSet[E]
	mu sync.RWMutex
}

// NewConcurrentSet creates a new thread-safe set wrapping the given mutable set.
func NewConcurrentSet[E any](innerSet ds.MutableSet[E]) *ConcurrentSet[E] {
	return &ConcurrentSet[E]{
		v:  innerSet,
		mu: sync.RWMutex{},
	}
}

// Contains returns true if the element is in the set.
func (s *ConcurrentSet[E]) Contains(e E) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Contains(e)
}

// Add adds an element to the set.
func (s *ConcurrentSet[E]) Add(e E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Add(e)
}

// AddAll adds multiple elements to the set.
func (s *ConcurrentSet[E]) AddAll(es ...E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.AddAll(es...)
}

// Remove removes an element from the set.
func (s *ConcurrentSet[E]) Remove(e E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Remove(e)
}

// RemoveAll removes multiple elements from the set.
func (s *ConcurrentSet[E]) RemoveAll(es ...E) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.RemoveAll(es...)
}

// Clear removes all elements from the set.
func (s *ConcurrentSet[E]) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Clear()
}

// Equal returns true if both sets contain exactly the same elements.
func (s *ConcurrentSet[E]) Equal(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Equal(other.Unfreeze())
}

// Size returns the number of elements in the set.
func (s *ConcurrentSet[_]) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Size()
}

// Cardinality returns the number of elements in the set.
func (s *ConcurrentSet[_]) Cardinality() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.Cardinality()
}

// IsEmpty returns true if the set contains no elements.
func (s *ConcurrentSet[_]) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsEmpty()
}

// Union returns a new concurrent set containing all elements from both sets.
func (s *ConcurrentSet[E]) Union(other ds.Set[E]) ds.ConcurrentSet[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return NewConcurrentSet(s.v.Union(other.Unfreeze()))
}

// Intersection returns a new concurrent set containing only elements present in both sets.
func (s *ConcurrentSet[E]) Intersection(other ds.Set[E]) ds.ConcurrentSet[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return NewConcurrentSet(s.v.Intersection(other.Unfreeze()))
}

// Difference returns a new concurrent set containing elements in this set but not in the other.
func (s *ConcurrentSet[E]) Difference(other ds.Set[E]) ds.ConcurrentSet[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return NewConcurrentSet(s.v.Difference(other.Unfreeze()))
}

// SymmetricDifference returns a new concurrent set containing elements in either set but not both.
func (s *ConcurrentSet[E]) SymmetricDifference(other ds.Set[E]) ds.ConcurrentSet[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return NewConcurrentSet(s.v.SymmetricDifference(other.Unfreeze()))
}

// SubSets returns all possible subsets of this set (power set).
func (s *ConcurrentSet[E]) SubSets() []ds.Set[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sliceutils.Map(s.v.SubSets(), func(subset ds.MutableSet[E]) ds.Set[E] {
		return subset.Freeze()
	})
}

// IsSubSet returns true if all elements of this set are in the other set.
func (s *ConcurrentSet[E]) IsSubSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsSubSet(other.Unfreeze())
}

// IsProperSubSet returns true if this is a subset of other and they are not equal.
func (s *ConcurrentSet[E]) IsProperSubSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsProperSubSet(other.Unfreeze())
}

// IsSuperSet returns true if all elements of the other set are in this set.
func (s *ConcurrentSet[E]) IsSuperSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsSuperSet(other.Unfreeze())
}

// IsProperSuperSet returns true if this is a superset of other and they are not equal.
func (s *ConcurrentSet[E]) IsProperSuperSet(other ds.Set[E]) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.IsProperSuperSet(other.Unfreeze())
}

// IterSubSets returns an iterator over all possible subsets of this set.
func (s *ConcurrentSet[E]) IterSubSets() iter.Seq[ds.Set[E]] {
	return func(yield func(ds.Set[E]) bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for subset := range s.v.IterSubSets() {
			if !yield(subset.Freeze()) {
				return
			}
		}
	}
}

// List returns a slice of all elements in the set.
func (s *ConcurrentSet[E]) List() []E {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v.List()
}

// Clone returns a new concurrent set with a copy of the data.
func (s *ConcurrentSet[E]) Clone() ds.ConcurrentSet[E] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return NewConcurrentSet(s.v.Clone())
}

// Iter returns an iterator over all elements in the set.
func (s *ConcurrentSet[E]) Iter() iter.Seq[E] {
	return func(yield func(E) bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for e := range s.v.Iter() {
			if !yield(e) {
				return
			}
		}
	}
}

// Iter2 returns an iterator with index and element pairs.
func (s *ConcurrentSet[E]) Iter2() iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for i, e := range s.v.Iter2() {
			if !yield(i, e) {
				return
			}
		}
	}
}

// Compute atomically computes a new value based on the element's presence.
// The remappingFunction receives the element and whether it exists, returning
// the new value and whether to store it.
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

// ComputeIfAbsent atomically computes a value only if the element is absent.
// The mappingFunction returns the value to store and whether to store it.
// If the element exists, returns the element without calling mappingFunction.
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

// ComputeIfPresent atomically computes a new value only if the element is present.
// The remappingFunction returns the new value and whether to keep it (false removes the element).
// If the element is absent, returns the element without calling remappingFunction.
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
