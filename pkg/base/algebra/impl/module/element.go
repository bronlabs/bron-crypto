package module

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type ModuleElement[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] struct {
	group.AdditiveGroupElement[M, E]

	H HolesModuleElement[M, BR, E, S]
}

type ModuleScalar[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] struct {
	ring.RingElement[BR, S]

	H HolesModuleScalar[M, BR, E, S]
}

type OneDimensionalModuleElement[M algebra.OneDimensionalModule[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.OneDimensionalModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] struct {
	ModuleElement[M, BR, E, S]
	group.CyclicGroupElement[M, E]

	H HolesOneDimensionalModuleElement[M, BR, E, S]
}
