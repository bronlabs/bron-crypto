package set

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type PointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]] struct{}

func (*PointedSetElement[S, E]) Equal(x E) bool {
	panic("in mixin")
}

func (*PointedSetElement[S, E]) Structure() algebra.PointedSet[S, E] {
	panic("in mixin")
}

func (e *PointedSetElement[S, E]) IsBasePoint() bool {
	return e.Equal(e.Structure().BasePoint())
}
