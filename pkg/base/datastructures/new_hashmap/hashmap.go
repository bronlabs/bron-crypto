package newHashmap

type HashMap[K any, V any] interface {
	Get(key K) (value V, exists bool)
	Put(key K, newValue V) (replaced bool, oldValue V)
	Clear()
	IsEmpty() bool
	Size() int
	ContainsKey(key K) bool
	Remove(key K) (removed bool, removedValue V)
}
