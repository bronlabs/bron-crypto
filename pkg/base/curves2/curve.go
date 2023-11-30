package curves2

type Curve interface {
	Name() string
	FieldElement() FieldElement
	Point() Point
	ScalarBaseMul(scalar Scalar) Point
}

type PairingCurve interface {
	G1() PairingPoint
	G2() PairingPoint
	Gt() GroupElement

	Pairing(p1, p2 PairingPoint) Scalar
	MultiPairing(...PairingPoint) Scalar
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
