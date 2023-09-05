package fuzz

import (
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
)

type Value struct {
	value string
}

func (k Value) Hash() [32]byte {
	return sha3.Sum256([]byte(k.value))
}

func Fuzz_Test_new(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
	})
}

func Fuzz_Test_get(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		s := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s.Get(Value{value: string(b)})
	})
}

func Fuzz_Test_contains(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		s := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s.Contains(Value{value: string(b)})
	})
}

func Fuzz_Test_remove(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		s := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s.Remove(Value{value: string(b)})
	})
}

func Fuzz_Test_union(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		s1 := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s2 := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s1.Union(s2)
	})
}

func Fuzz_Test_diff(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		s1 := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s2 := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s1.Difference(s2)
	})
}

func Fuzz_Test_intersect(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		s1 := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s2 := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s1.Intersection(s2)
	})
}

func Fuzz_Test_len(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		s := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s.Len()
	})
}

func Fuzz_Test_clear(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		s := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s.Clear()
	})
}

func Fuzz_Test_isempty(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		s := hashset.NewHashSet[Value]([]Value{
			{value: string(a)},
		})
		s.IsEmpty()
	})
}
