package set

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type HolesPointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]] interface {
	Equal(x E) bool
	Structure() S
}

func NewPointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]](H HolesPointedSetElement[S, E]) PointedSetElement[S, E] {
	return PointedSetElement[S, E]{
		H: H,
	}
}
