package algebra

type AffineSystem[E AffineElement[E, C], C RingElement[C]] interface {
	Structure[E]

	FromAffineCompressed(b []byte) (E, error)
	FromAffineUncompressed(b []byte) (E, error)
}

type AffineElement[E Element[E], C RingElement[C]] interface {
	Element[E]
	Coordinates() []C

	// TODO(aalireza): we should probably rename these, technically they represent chosen method of serialisation (e.g. secg for Weierstrass curves, zcash for BLS12381, and RFCxxx for Edwards)
	ToAffineCompressed() []byte
	ToAffineUncompressed() []byte
}

type AlgebraicCurve[Point AlgebraicPoint[Point, Coordinate], Coordinate RingElement[Coordinate]] interface {
	Group[Point]
	AffineSystem[Point, Coordinate]

	NewPoint(affineX, affineY Coordinate) (Point, error)
	HashWithDst(dst string, message []byte) (Point, error)
}

type AlgebraicPoint[Point interface {
	GroupElement[Point]
	AffineElement[Point, Coordinate]
}, Coordinate RingElement[Coordinate]] interface {
	GroupElement[Point]
	AffineElement[Point, Coordinate]

	AffineX() Coordinate
	AffineY() Coordinate
}

type GenericEllipticCurve[
	Point GenericEllipticCurvePoint[Point, BaseFieldElement, Scalar, TorsionFreePoint, TorsionFreeScalar], BaseFieldElement FiniteFieldElement[BaseFieldElement], Scalar UintLike[Scalar],
	TorsionFreePoint TorsionFreeEllipticCurvePoint[TorsionFreePoint, BaseFieldElement, TorsionFreeScalar], TorsionFreeScalar PrimeFieldElement[TorsionFreeScalar],
] interface {
	AlgebraicCurve[Point, BaseFieldElement]
	FiniteAbelianGroup[Point, Scalar]
	TorsionFreeSubGroupGenerator() TorsionFreePoint

	ScalarField() PrimeField[TorsionFreeScalar]
	BaseField() FiniteField[BaseFieldElement]
}

type GenericEllipticCurvePoint[Point interface {
	AlgebraicPoint[Point, BaseFieldElement]
	FiniteAbelianGroupElement[Point, Scalar]
}, BaseFieldElement FiniteFieldElement[BaseFieldElement], Scalar UintLike[Scalar],
	TorsionFreePoint TorsionFreeEllipticCurvePoint[TorsionFreePoint, BaseFieldElement, TorsionFreeScalar], TorsionFreeScalar PrimeFieldElement[TorsionFreeScalar],
] interface {
	AlgebraicPoint[Point, BaseFieldElement]
	AbelianGroupElement[Point, Scalar]

	ClearCofactor() TorsionFreePoint
}

type TorsionFreeEllipticCurve[Point TorsionFreeEllipticCurvePoint[Point, BaseFieldElement, Scalar],
	BaseFieldElement FiniteFieldElement[BaseFieldElement], Scalar PrimeFieldElement[Scalar],
] interface {
	GenericEllipticCurve[Point, BaseFieldElement, Scalar, Point, Scalar]
	PrimeGroup[Point, Scalar]
	CyclicSemiGroup[Point]
}

type TorsionFreeEllipticCurvePoint[Point interface {
	AlgebraicPoint[Point, BaseFieldElement]
	PrimeGroupElement[Point, Scalar]
	CyclicSemiGroupElement[Point]
	ClearCofactor() Point
}, BaseFieldElement FiniteFieldElement[BaseFieldElement], Scalar PrimeFieldElement[Scalar]] interface {
	AlgebraicPoint[Point, BaseFieldElement]
	PrimeGroupElement[Point, Scalar]
	CyclicSemiGroupElement[Point]

	ClearCofactor() Point
}

type PairingFriendlyCurve[P TorsionFreeEllipticCurvePoint[P, B, S], B FiniteFieldElement[B], S PrimeFieldElement[S], P2 TorsionFreeEllipticCurvePoint[P2, B2, S], B2 FiniteFieldElement[B2]] interface {
	TorsionFreeEllipticCurve[P, B, S]

	OtherCurve() TorsionFreeEllipticCurve[P2, B2, S]
}

type Pairing[
	g1 TorsionFreeEllipticCurve[g1Point, g1Coordinate, Scalar], g1Point TorsionFreeEllipticCurvePoint[g1Point, g1Coordinate, Scalar], g1Coordinate FiniteFieldElement[g1Coordinate],
	g2 TorsionFreeEllipticCurve[g2Point, g2Coordinate, Scalar], g2Point TorsionFreeEllipticCurvePoint[g2Point, g2Coordinate, Scalar], g2Coordinate FiniteFieldElement[g2Coordinate],
	gt interface {
		MultiplicativeGroup[gtElement]
		FiniteAbelianGroup[gtElement, Scalar]
	}, gtElement interface {
		MultiplicativeGroupElement[gtElement]
		FiniteAbelianGroupElement[gtElement, Scalar]
	}, Scalar PrimeFieldElement[Scalar],
] interface {
	G1() g1
	G2() g2
	Gt() gt

	Pair(p g1Point, q g2Point) (gtElement, error)
	MultiPair(ps []g1Point, qs []g2Point) (gtElement, error)
}
