package algebra

type AffineSystem[E AffineElement[E, C], C RingElement[C]] interface {
	Structure[E]

	FromAffineCompressed(b []byte) (E, error)
	FromAffineUncompressed(b []byte) (E, error)
}

type AffineElement[E Element[E], C RingElement[C]] interface {
	Element[E]
	Coordinates() []C

	ToAffineCompressed() []byte
	ToAffineUncompressed() []byte
}

type AlgebraicCurve[Point AlgebraicPoint[Point, Coordinate], Coordinate RingElement[Coordinate]] interface {
	Group[Point]
	AffineSystem[Point, Coordinate]

	NewPoint(x, y Coordinate) (Point, error)
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

type EllipticCurve[Point EllipticCurvePoint[Point, BaseRingElement, Scalar],
	BaseRingElement RingElement[BaseRingElement], Scalar RingElement[Scalar],
] interface {
	AlgebraicCurve[Point, BaseRingElement]
	AbelianGroup[Point, Scalar]

	PrimeSubGroupGenerator() Point
}

type EllipticCurvePoint[Point interface {
	AlgebraicPoint[Point, BaseRingElement]
	AbelianGroupElement[Point, Scalar]
}, BaseRingElement RingElement[BaseRingElement], Scalar RingElement[Scalar]] interface {
	AlgebraicPoint[Point, BaseRingElement]
	AbelianGroupElement[Point, Scalar]
}

type Pairing[
	g1 EllipticCurve[g1Point, g1Coordinate, g1Scalar], g1Point EllipticCurvePoint[g1Point, g1Coordinate, g1Scalar], g1Coordinate RingElement[g1Coordinate], g1Scalar RingElement[g1Scalar],
	g2 EllipticCurve[g2Point, g2Coordinate, g2Scalar], g2Point EllipticCurvePoint[g2Point, g2Coordinate, g2Scalar], g2Coordinate RingElement[g2Coordinate], g2Scalar RingElement[g2Scalar],
	gt interface {
		MultiplicativeGroup[gtElement]
		AbelianGroup[gtElement, gtScalar]
	}, gtElement interface {
		MultiplicativeGroupElement[gtElement]
		AbelianGroupElement[gtElement, gtScalar]
	}, gtScalar RingElement[gtScalar],
] interface {
	G1() g1
	G2() g2
	Gt() gt

	Pair(p g1Point, q g2Point) (gtElement, error)
	MultiPair(ps []g1Point, qs []g2Point) (gtElement, error)
}

// aliases
type Curve[
	Point EllipticCurvePoint[Point, BaseRingElement, Scalar],
	BaseRingElement RingElement[BaseRingElement], Scalar RingElement[Scalar],
] = EllipticCurve[Point, BaseRingElement, Scalar]

type Point[
	Point EllipticCurvePoint[Point, BaseRingElement, Scalar],
	BaseRingElement RingElement[BaseRingElement], Scalar RingElement[Scalar],
] = EllipticCurvePoint[Point, BaseRingElement, Scalar]
