package impl

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type PointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]] struct {
	algebra.PointedSetElement[S, E]
}

func (e *PointedSetElement[S, E]) IsBasePoint() bool {
	return e.Equal(e.Structure().BasePoint())
}
