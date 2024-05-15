package set

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type PointedSetElement[S algebra.PointedSet[S, E], E algebra.PointedSetElement[S, E]] struct {
	H HolesPointedSetElement[S, E]
}

func (e *PointedSetElement[S, E]) IsBasePoint() bool {
	return e.H.Equal(e.H.Structure().BasePoint())
}
