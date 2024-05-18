package boolean

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
)

type ConjunctiveGroupoid[G algebra.ConjunctiveGroupoid[G, E], E algebra.ConjunctiveGroupoidElement[G, E]] struct {
	groupoid.Groupoid[G, E]

	H HolesConjunctiveGroupoid[G, E]
}

func (g *ConjunctiveGroupoid[G, E]) Add(x algebra.ConjunctiveGroupoidElement[G, E], ys ...algebra.ConjunctiveGroupoidElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.And(y)
	}
	return sum.Unwrap()
}
