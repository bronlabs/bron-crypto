package datastructures

type BiMap[K any, V any] interface {
	Map[K, V]
	Reverse() BiMap[V, K]
}
