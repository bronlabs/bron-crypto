package hashset_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"pgregory.net/rapid"
)

// Common generators for all hashset property tests

// ElementGenerator generates string elements (comparable type)
func ElementGenerator() *rapid.Generator[string] {
	return rapid.String()
}

// MutableComparableSetGenerator generates populated MutableComparable set
func MutableComparableSetGenerator() *rapid.Generator[ds.MutableSet[string]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableSet[string] {
		elements := rapid.SliceOf(ElementGenerator()).Draw(t, "elements")
		return hashset.NewComparable(elements...)
	})
}

// NonEmptyMutableComparableSetGenerator generates non-empty mutable set
func NonEmptyMutableComparableSetGenerator() *rapid.Generator[ds.MutableSet[string]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableSet[string] {
		elements := rapid.SliceOfN(ElementGenerator(), 1, -1).Draw(t, "elements")
		return hashset.NewComparable(elements...)
	})
}

// ImmutableComparableSetGenerator generates populated immutable set
func ImmutableComparableSetGenerator() *rapid.Generator[ds.Set[string]] {
	return rapid.Custom(func(t *rapid.T) ds.Set[string] {
		elements := rapid.SliceOf(ElementGenerator()).Draw(t, "elements")
		return hashset.NewComparable(elements...).Freeze()
	})
}

// HashableElement is a test type that implements ds.Hashable[*HashableElement]
type HashableElement struct {
	Value string
}

func (e *HashableElement) Equal(other *HashableElement) bool {
	return e.Value == other.Value
}

func (e *HashableElement) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range e.Value {
		h = h.Combine(base.HashCode(c))
	}
	return h
}

// HashableElementGenerator generates *HashableElement values
func HashableElementGenerator() *rapid.Generator[*HashableElement] {
	return rapid.Custom(func(t *rapid.T) *HashableElement {
		return &HashableElement{Value: rapid.String().Draw(t, "value")}
	})
}

// MutableHashableSetGenerator generates populated MutableHashable set
func MutableHashableSetGenerator() *rapid.Generator[ds.MutableSet[*HashableElement]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableSet[*HashableElement] {
		elements := rapid.SliceOf(HashableElementGenerator()).Draw(t, "elements")
		s := hashset.NewHashable[*HashableElement]()
		for _, e := range elements {
			s.Add(e)
		}
		return s
	})
}

// NonEmptyMutableHashableSetGenerator generates non-empty hashable set
func NonEmptyMutableHashableSetGenerator() *rapid.Generator[ds.MutableSet[*HashableElement]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableSet[*HashableElement] {
		elements := rapid.SliceOfN(HashableElementGenerator(), 1, -1).Draw(t, "elements")
		s := hashset.NewHashable[*HashableElement]()
		for _, e := range elements {
			s.Add(e)
		}
		return s
	})
}

// ImmutableHashableSetGenerator generates immutable hashable set
func ImmutableHashableSetGenerator() *rapid.Generator[ds.Set[*HashableElement]] {
	return rapid.Custom(func(t *rapid.T) ds.Set[*HashableElement] {
		s := MutableHashableSetGenerator().Draw(t, "mutable")
		return s.Freeze()
	})
}

// ConcurrentSetGenerator generates ConcurrentSet with comparable inner
func ConcurrentSetGenerator() *rapid.Generator[*hashset.ConcurrentSet[string]] {
	return rapid.Custom(func(t *rapid.T) *hashset.ConcurrentSet[string] {
		inner := MutableComparableSetGenerator().Draw(t, "inner")
		return hashset.NewConcurrentSet(inner)
	})
}

// NonEmptyConcurrentSetGenerator generates non-empty concurrent set
func NonEmptyConcurrentSetGenerator() *rapid.Generator[*hashset.ConcurrentSet[string]] {
	return rapid.Custom(func(t *rapid.T) *hashset.ConcurrentSet[string] {
		inner := NonEmptyMutableComparableSetGenerator().Draw(t, "inner")
		return hashset.NewConcurrentSet(inner)
	})
}

// SmallMutableComparableSetGenerator generates small sets (for SubSets tests)
func SmallMutableComparableSetGenerator() *rapid.Generator[ds.MutableSet[string]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableSet[string] {
		elements := rapid.SliceOfN(ElementGenerator(), 0, 5).Draw(t, "elements")
		return hashset.NewComparable(elements...)
	})
}

// SmallMutableHashableSetGenerator generates small hashable sets (for SubSets tests)
func SmallMutableHashableSetGenerator() *rapid.Generator[ds.MutableSet[*HashableElement]] {
	return rapid.Custom(func(t *rapid.T) ds.MutableSet[*HashableElement] {
		elements := rapid.SliceOfN(HashableElementGenerator(), 0, 5).Draw(t, "elements")
		s := hashset.NewHashable[*HashableElement]()
		for _, e := range elements {
			s.Add(e)
		}
		return s
	})
}

// SmallImmutableComparableSetGenerator generates small immutable sets (for SubSets tests)
func SmallImmutableComparableSetGenerator() *rapid.Generator[ds.Set[string]] {
	return rapid.Custom(func(t *rapid.T) ds.Set[string] {
		s := SmallMutableComparableSetGenerator().Draw(t, "mutable")
		return s.Freeze()
	})
}

// SmallConcurrentSetGenerator generates small concurrent sets (for SubSets tests)
func SmallConcurrentSetGenerator() *rapid.Generator[*hashset.ConcurrentSet[string]] {
	return rapid.Custom(func(t *rapid.T) *hashset.ConcurrentSet[string] {
		inner := SmallMutableComparableSetGenerator().Draw(t, "inner")
		return hashset.NewConcurrentSet(inner)
	})
}
