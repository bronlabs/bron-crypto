package module

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type HolesModule[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] interface {
	group.HolesAdditiveGroup[M, E]
}

type HolesModuleBaseRing[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] interface {
	ring.HolesRing[BR, S]
}

type HolesModuleElement[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] interface {
	group.HolesAdditiveGroupElement[M, E]
}

type HolesModuleScalar[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] interface {
	ring.HolesRingElement[BR, S]
}

type HolesOneDimensionalModule[M algebra.OneDimensionalModule[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.OneDimensionalModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] interface {
	HolesModule[M, BR, E, S]
	group.HolesCyclicGroup[M, E]
}

type HolesOneDimensionalModuleElement[M algebra.OneDimensionalModule[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.OneDimensionalModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] interface {
	HolesModuleElement[M, BR, E, S]
	group.HolesCyclicGroupElement[M, E]
}

func NewModule[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]](H HolesModule[M, BR, E, S], baseRingConstructor func() BR) Module[M, BR, E, S] {
	return Module[M, BR, E, S]{
		AdditiveGroup: group.NewAdditiveGroup[M, E](H),
		_ring:         baseRingConstructor,
		H:             H,
	}
}

func NewModuleElement[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]](H HolesModuleElement[M, BR, E, S]) ModuleElement[M, BR, E, S] {
	return ModuleElement[M, BR, E, S]{
		AdditiveGroupElement: group.NewAdditiveGroupElement[M, E](H),
		H:                    H,
	}
}

func NewModuleBaseRing[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]](H HolesModuleBaseRing[M, BR, E, S], moduleConstructor func() M) ModuleBaseRing[M, BR, E, S] {
	return ModuleBaseRing[M, BR, E, S]{
		Ring:    ring.NewRing[BR, S](H),
		_module: moduleConstructor,
		H:       H,
	}
}

func NewModuleScalar[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]](H HolesModuleScalar[M, BR, E, S]) ModuleScalar[M, BR, E, S] {
	return ModuleScalar[M, BR, E, S]{
		RingElement: ring.NewRingElement[BR, S](H),
		H:           H,
	}
}

func NewOneDimensionalModule[M algebra.OneDimensionalModule[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.OneDimensionalModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]](H HolesOneDimensionalModule[M, BR, E, S], baseRingConstructor func() BR) OneDimensionalModule[M, BR, E, S] {
	return OneDimensionalModule[M, BR, E, S]{
		Module:      NewModule(H, baseRingConstructor),
		CyclicGroup: group.NewCyclicGroup(H),
		H:           H,
	}
}

func NewOneDimensionalModuleElement[M algebra.OneDimensionalModule[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.OneDimensionalModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]](H HolesOneDimensionalModuleElement[M, BR, E, S]) OneDimensionalModuleElement[M, BR, E, S] {
	return OneDimensionalModuleElement[M, BR, E, S]{
		ModuleElement:      NewModuleElement(H),
		CyclicGroupElement: group.NewCyclicGroupElement(H),
		H:                  H,
	}
}
