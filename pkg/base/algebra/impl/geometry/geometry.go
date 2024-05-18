package geometry

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/field"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
)

type AlgebraicVariety[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]] struct {
	_field func() BF
}

func (v *AlgebraicVariety[V, BF, E, FE]) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[V, BF, E, FE] {
	return v._field()
}

type AlgebraicVarietyElement[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]] struct {
}

type AlgebraicVarietyBaseField[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]] struct {
	field.Field[BF, FE]
	_variety func() V

	H HolesAlgebraicVarietyBaseField[V, BF, E, FE]
}

func (bf *AlgebraicVarietyBaseField[V, BF, E, FE]) AlgebraicVariety() algebra.AlgebraicVariety[V, BF, E, FE] {
	return bf._variety()
}

type AlgebraicVarietyBaseFieldElement[V algebra.AlgebraicVariety[V, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, E, FE], E algebra.AlgebraicVarietyElement[V, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, E, FE]] struct {
	field.FieldElement[BF, FE]

	H HolesAlgebraicVarietyBaseFieldElement[V, BF, E, FE]
}

type AffineAlgebraicVarietyElement[V algebra.AlgebraicVariety[V, BF, AE, FE], BF algebra.AlgebraicVarietyBaseField[V, BF, AE, FE], AE algebra.AffineAlgebraicVarietyElement[V, BF, AE, FE], FE algebra.AlgebraicVarietyBaseFieldElement[V, BF, AE, FE]] struct {
	AlgebraicVarietyElement[V, BF, AE, FE]
}

type AlgebraicGroup[G algebra.AlgebraicGroup[G, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[G, BF, E, FE], E algebra.AlgebraicGroupElement[G, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[G, BF, E, FE]] struct {
	group.Group[G, E]
	AlgebraicVariety[G, BF, E, FE]

	H HolesAlgebraicGroup[G, BF, E, FE]
}

type AlgebraicGroupElement[G algebra.AlgebraicGroup[G, BF, E, FE], BF algebra.AlgebraicVarietyBaseField[G, BF, E, FE], E algebra.AlgebraicGroupElement[G, BF, E, FE], FE algebra.AlgebraicVarietyBaseFieldElement[G, BF, E, FE]] struct {
	group.GroupElement[G, E]
	AlgebraicVarietyElement[G, BF, E, FE]

	H HolesAlgebraicGroupElement[G, BF, E, FE]
}

type AlgebraicCurve[C algebra.AlgebraicCurve[C, BF, P, FE], BF algebra.AlgebraicVarietyBaseField[C, BF, P, FE], P algebra.Point[C, BF, P, FE], FE algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]] struct {
	AlgebraicVariety[C, BF, P, FE]

	H HolesAlgebraicCurve[C, BF, P, FE]
}

func (c *AlgebraicCurve[C, BF, P, FE]) FrobeniusEndomorphism(p P) P {
	char := c.AlgebraicVarietyBaseField().Characteristic()
	result, err := c.H.NewPoint(p.AffineX().Exp(char), p.AffineY().Exp(char))
	if err != nil {
		panic(err)
	}
	return result
}

type Point[C algebra.AlgebraicCurve[C, BF, P, FE], BF algebra.AlgebraicVarietyBaseField[C, BF, P, FE], P algebra.Point[C, BF, P, FE], FE algebra.AlgebraicVarietyBaseFieldElement[C, BF, P, FE]] struct {
	AlgebraicVarietyElement[C, BF, P, FE]

	H HolesPoint[C, BF, P, FE]
}

func (p *Point[C, BF, P, FE]) AffineCoordinates() []FE {
	return []FE{p.H.AffineX(), p.H.AffineY()}
}
