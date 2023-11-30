package curves2

type Curve interface {
	Name() string
	FieldElement() FieldElement
	Point() Point
	ScalarBaseMul(scalar Scalar) Point
}

type ShortWeierstrassCurve interface {
	ShortWeierstrassA() FieldElement
	ShortWeierstrassB() FieldElement
}

type MontgomeryCurve interface {
	MontgomeryA() FieldElement
	MontgomeryB() FieldElement
}

type TwistedEdwardsCurve interface {
	TwistedEdwardsA() FieldElement
	TwistedEdwardsD() FieldElement
}
