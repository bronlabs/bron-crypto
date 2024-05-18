package geometry

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/field"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
)

type HolesAlgebraicVarietyBaseField[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]] interface {
	field.HolesField[BF, FE]
}

type HolesAlgebraicVarietyBaseFieldElement[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]] interface {
	field.HolesFieldElement[BF, FE]
}

type HolesAlgebraicGroup[G algebra.AlgebraicGroup[G, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[G, BF, E, FE], E algebra.AlgebraicGroupElement[G, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[G, BF, E, FE]] interface {
	group.HolesGroup[G, E]
}

type HolesAlgebraicGroupElement[G algebra.AlgebraicGroup[G, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[G, BF, E, FE], E algebra.AlgebraicGroupElement[G, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[G, BF, E, FE]] interface {
	group.HolesGroupElement[G, E]
}

type HolesAlgebraicCurve[C algebra.AlgebraicCurve[C, BF, P, FE], BF algebra.AlgebraicVarietyBaseField[C, BF, P, FE], P algebra.Point[C, BF, P, FE], FE algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]] interface {
	NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]) (P, error)
}

type HolesPoint[C algebra.AlgebraicCurve[C, BF, P, FE], BF algebra.AlgebraicVarietyBaseField[C, BF, P, FE], P algebra.Point[C, BF, P, FE], FE algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]] interface {
	AffineX() FE
	AffineY() FE
}

func NewAlgebraicVariety[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]](fieldConstructor func() BF) AlgebraicVariety[V, BF, E, FE] {
	return AlgebraicVariety[V, BF, E, FE]{
		_field: fieldConstructor,
	}
}

func NewAlgebraicVarietyElement[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]]() AlgebraicVarietyElement[V, BF, E, FE] {
	return AlgebraicVarietyElement[V, BF, E, FE]{}
}

func NewAlgebraicVarietyBaseField[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]](H HolesAlgebraicVarietyBaseField[V, BF, E, FE], varietyConstructor func() V) AlgebraicVarietyBaseField[V, BF, E, FE] {
	return AlgebraicVarietyBaseField[V, BF, E, FE]{
		Field:    field.NewField(H),
		_variety: varietyConstructor,
		H:        H,
	}
}

func NewAlgebraicVarietyBaseFieldElement[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]](H HolesAlgebraicVarietyBaseFieldElement[V, BF, E, FE]) AlgebraicVarietyBaseFieldElement[V, BF, E, FE] {
	return AlgebraicVarietyBaseFieldElement[V, BF, E, FE]{
		FieldElement: field.NewFieldElement(H),
		H:            H,
	}
}

func NewAffineAlgebraicVarietyElement[V algebra.AlgebraicVariety[V, BF, AE, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, AE, FE], AE algebra.AffineAlgebraicVarietyElement[V, BF, AE, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, AE, FE]]() AffineAlgebraicVarietyElement[V, BF, AE, FE] {
	return AffineAlgebraicVarietyElement[V, BF, AE, FE]{
		AlgebraicVarietyElement: NewAlgebraicVarietyElement[V, BF, AE, FE](),
	}
}

func NewAlgebraicGroup[G algebra.AlgebraicGroup[G, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[G, BF, E, FE], E algebra.AlgebraicGroupElement[G, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[G, BF, E, FE]](H HolesAlgebraicGroup[G, BF, E, FE], fieldConstructor func() BF) AlgebraicGroup[G, BF, E, FE] {
	return AlgebraicGroup[G, BF, E, FE]{
		Group:            group.NewGroup(H),
		AlgebraicVariety: NewAlgebraicVariety(fieldConstructor),
		H:                H,
	}
}

func NewAlgebraicGroupElement[G algebra.AlgebraicGroup[G, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[G, BF, E, FE], E algebra.AlgebraicGroupElement[G, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[G, BF, E, FE]](H HolesAlgebraicGroupElement[G, BF, E, FE]) AlgebraicGroupElement[G, BF, E, FE] {
	return AlgebraicGroupElement[G, BF, E, FE]{
		GroupElement:            group.NewGroupElement(H),
		AlgebraicVarietyElement: NewAlgebraicVarietyElement[G, BF, E, FE](),
		H:                       H,
	}
}

func NewAlgebraicCurve[C algebra.AlgebraicCurve[C, BF, P, FE], BF algebra.AlgebraicVarietyBaseField[C, BF, P, FE], P algebra.Point[C, BF, P, FE], FE algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]](H HolesAlgebraicCurve[C, BF, P, FE], fieldConstructor func() BF) AlgebraicCurve[C, BF, P, FE] {
	return AlgebraicCurve[C, BF, P, FE]{
		AlgebraicVariety: NewAlgebraicVariety[C, BF, P, FE](fieldConstructor),
		H:                H,
	}
}

func NewPoint[C algebra.AlgebraicCurve[C, BF, P, FE], BF algebra.AlgebraicVarietyBaseField[C, BF, P, FE], P algebra.Point[C, BF, P, FE], FE algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]](H HolesPoint[C, BF, P, FE]) Point[C, BF, P, FE] {
	return Point[C, BF, P, FE]{
		AlgebraicVarietyElement: NewAlgebraicVarietyElement[C, BF, P, FE](),
		H:                       H,
	}
}
