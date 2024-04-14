package mixins

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type PointedSet[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]] struct {
	algebra.PointedSet[S, E]
}

type PointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]] struct {
	algebra.PointedSetElement[S, E]
}

func (e *PointedSetElement[S, E]) IsBasePoint() bool {
	return e.Equal(e.Structure().BasePoint())
}
