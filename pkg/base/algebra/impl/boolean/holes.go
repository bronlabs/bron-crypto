package boolean

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
)

type HolesConjunctiveGroupoid[G algebra.ConjunctiveGroupoid[G, E], E algebra.ConjunctiveGroupoidElement[G, E]] interface {
	groupoid.HolesGroupoid[G, E]
}
