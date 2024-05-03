package testutils

import "pgregory.net/rapid"

type Map[K, V any] any

type AbstractMapAdapters[T comparable, M Map[K, V], K, V any] interface {
	Key(T) K
	UnwrapKey(K) T
	Value(T) K
	UnwrapValue(K) T
	Map([]T, []V) M
	UnwrapMap(M) ([]T, []V)
	Empty() M
}

type MapAdapters[M Map[K, V], K, V any] AbstractMapAdapters[uint, Map[K, V], K, V]

type MapPropertyTester[M Map[K, V], K, V any] struct {
	Adapters            MapAdapters[M, K, V]
	MaxNumberOfElements int
	BoundedIntGenerator *rapid.Generator[int]
}

func (pt *MapPropertyTester[M, K, V]) VariableSizeGenerator() *rapid.Generator[K]

func (pt *MapPropertyTester[M, K, V]) FixedSizeGenerator(positiveSize int) *rapid.Generator[K]

func (pt *MapPropertyTester[M, K, V]) KeyGenerator() *rapid.Generator[K]
func (pt *MapPropertyTester[M, K, V]) FixedSizeKeySliceGenerator(positiveSize int, distinct bool) *rapid.Generator[K]
func (pt *MapPropertyTester[M, K, V]) VariableSizeKeySliceGenerator(distinct bool) *rapid.Generator[K]

func (pt *MapPropertyTester[M, K, V]) ValueGenerator() *rapid.Generator[V]
func (pt *MapPropertyTester[M, K, V]) FixedSizeValueSliceGenerator(positiveSize int, distinct bool) *rapid.Generator[V]
func (pt *MapPropertyTester[M, K, V]) VariableSizeValueSliceGenerator(distinct bool) *rapid.Generator[V]
