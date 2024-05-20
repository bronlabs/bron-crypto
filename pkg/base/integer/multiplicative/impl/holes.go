package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/multiplicative"
	pimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/uints"
)

type HolesZnX[G multiplicative.ZnX[G, E], E multiplicative.IntX[G, E]] interface {
	group.HolesMultiplicativeGroup[G, E]
	pimpl.HolesNaturalPreSemiRing[G, E]
	order.HolesBoundedOrderTheoreticLattice[G, E]

	Modulus() uints.Uint
}

type HolesIntX[G multiplicative.ZnX[G, E], E multiplicative.IntX[G, E]] interface {
	group.HolesMultiplicativeGroupElement[G, E]
	pimpl.HolesNaturalPreSemiRingElement[G, E]
	order.HolesBoundedOrderTheoreticLatticeElement[G, E]
}
