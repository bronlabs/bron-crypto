package curves2

type Point interface {
	GroupElement
	FromAffineBytes(bytes []byte)
	FromAffineCompressedBytes(bytes []byte)
	Add(rhs Point) Point
	Neg() Point
	Mul(rhs Scalar) Point
	IsOnCurve() bool
	ClearCofactor() bool
	IsSmallOrder() bool
	IsTorsionFree() bool
	AffineBytes() []byte
	AffineCompressedBytes() []byte
	Curve() Curve
	Scalar() Scalar
	toAffine() AffinePoint
}

type PairingPoint interface {
	Point
	OtherGroup() PairingPoint
	Pairing(p PairingPoint) GroupElement
}

type AffinePoint interface {
	X() FieldElement
	Y() FieldElement
}

type ProjectivePoint interface {
	ProjectiveX() FieldElement
	ProjectiveY() FieldElement
	ProjectiveZ() FieldElement
}

type JacobianPoint interface {
	JacobianX() FieldElement
	JacobianY() FieldElement
	JacobianZ() FieldElement
}

type ExtendedPoint interface {
	ExtendedX() FieldElement
	ExtendedY() FieldElement
	ExtendedZ() FieldElement
	ExtendedT() FieldElement
}
