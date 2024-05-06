package testutils2

type Graph[NodeType Object] any

type AbstractGraphGenerator[T comparable, G Graph[N], N Object] interface {
	Node() AbstractObjectAdapter[T, N]
	Graph() AbstractObjectAdapter[T, G]

	Generator[G]
}
