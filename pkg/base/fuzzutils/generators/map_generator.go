package generators

import "golang.org/x/exp/constraints"

type mapGenerator[L constraints.Unsigned, K comparable, V any] struct {
	lenGen Generator[L]
	keyGen Generator[K]
	valGen Generator[V]
}

func NewMapGenerator[L constraints.Unsigned, K comparable, V any](lenGen Generator[L], keyGen Generator[K], valGen Generator[V]) Generator[map[K]V] {
	return &mapGenerator[L, K, V]{
		lenGen: lenGen,
		keyGen: keyGen,
		valGen: valGen,
	}
}

func (m *mapGenerator[L, K, V]) Generate() map[K]V {
	x := make(map[K]V)
	l := m.lenGen.Generate()
	for i := L(0); i < l; i++ {
		x[m.keyGen.Generate()] = m.valGen.Generate()
	}

	return x
}
