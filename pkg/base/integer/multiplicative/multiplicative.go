package multiplicative

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/uints"
)

type ZnX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroup[G, E]
	algebra.BoundedOrderTheoreticLattice[G, E]
	integer.NaturalSemiRing[G, E]

	Modulus() uints.Uint
}

type IntX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroupElement[G, E]
	algebra.BoundedOrderTheoreticLatticeElement[G, E]
	integer.NaturalSemiRingElement[G, E]
}
