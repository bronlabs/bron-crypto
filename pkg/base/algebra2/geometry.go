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
}

type AlgebraicPoint[Point interface {
	GroupElement[Point]
	AffineElement[Point, Coordinate]
}, Coordinate RingElement[Coordinate]] interface {
	GroupElement[Point]
	AffineElement[Point, Coordinate]

	AffineX() (Coordinate, error)
	AffineY() (Coordinate, error)
}

type GenericEllipticCurve[
	Point GenericEllipticCurvePoint[Point, BaseFieldElement, Scalar, TorsionFreePoint, TorsionFreeScalar], BaseFieldElement FiniteFieldElement[BaseFieldElement], Scalar UintLike[Scalar],
	TorsionFreePoint TorsionFreeEllipticCurvePoint[TorsionFreePoint, BaseFieldElement, TorsionFreeScalar], TorsionFreeScalar PrimeFieldElement[TorsionFreeScalar],
] interface {
	AlgebraicCurve[Point, BaseFieldElement]
	FiniteAbelianGroup[Point, Scalar]
	TorsionFreeSubGroupGenerator() TorsionFreePoint
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

type Pairing[
	g1 TorsionFreeEllipticCurve[g1Point, g1Coordinate, g1Scalar], g1Point TorsionFreeEllipticCurvePoint[g1Point, g1Coordinate, g1Scalar], g1Coordinate FiniteFieldElement[g1Coordinate], g1Scalar PrimeFieldElement[g1Scalar],
	g2 TorsionFreeEllipticCurve[g2Point, g2Coordinate, g2Scalar], g2Point TorsionFreeEllipticCurvePoint[g2Point, g2Coordinate, g2Scalar], g2Coordinate FiniteFieldElement[g2Coordinate], g2Scalar PrimeFieldElement[g2Scalar],
	gt interface {
		MultiplicativeGroup[gtElement]
		AbelianGroup[gtElement, gtScalar]
	}, gtElement interface {
		MultiplicativeGroupElement[gtElement]
		AbelianGroupElement[gtElement, gtScalar]
	}, gtScalar IntLike[gtScalar],
] interface {
	G1() g1
	G2() g2
	Gt() gt

	Pair(p g1Point, q g2Point) (gtElement, error)
	MultiPair(ps []g1Point, qs []g2Point) (gtElement, error)
}
