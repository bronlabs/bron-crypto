package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type ZnX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroup[G, E]
	algebra.BoundedOrderTheoreticLattice[G, E]
	NaturalRig[G, E]
}

type IntX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroupElement[G, E]
	NaturalRigElement[G, E]
}
