package crtp

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
)

type (
	CoordinateSystem string
	PairingAlgorithm string
)

const (
	AffineCoordinateSystem              CoordinateSystem = "Affine"
	ExtendedHomogeneousCoordinateSystem CoordinateSystem = "ExtendedHomogeneous"
	ProjectiveCoordinateSystem          CoordinateSystem = "Projective"
	JacobianCoordinateSystem            CoordinateSystem = "Jacobian"
)

func NewCoordinates[C any](t CoordinateSystem, v ...C) Coordinates[C] {
	return Coordinates[C]{v: v, t: t}
}

type Coordinates[C any] struct {
	v []C
	t CoordinateSystem
}

func (c Coordinates[C]) Value() []C {
	return c.v
}

func (c Coordinates[C]) Type() CoordinateSystem {
	return c.t
}

type Variety[E, C any] interface {
	Structure[E]

	FromCompressed(b []byte) (E, error)
	BaseStructure() Structure[C]
}

type RationalPoint[E, C any] interface {
	Element[E]

	Coordinates() Coordinates[C]
	ToCompressed() []byte
}

type AlgebraicCurve[P, C any] interface {
	Group[P]
	Variety[P, C]
}

type AlgebraicPoint[P, C any] interface {
	GroupElement[P]
	RationalPoint[P, C]
}

type AffineCurve[P, C any] interface {
	AlgebraicCurve[P, C]
	FromAffine(x, y C) (P, error)
}
type AffinePoint[P, C any] interface {
	AlgebraicPoint[P, C]
	AffineX() C
	AffineY() C
}

type ExtendedHomogeneousCurve[P, C any] interface {
	AlgebraicCurve[P, C]
	FromExtendedHomogeneous(x, y, z, t C) (P, error)
}

type ExtendedHomogeneousPoint[P, C any] interface {
	AlgebraicPoint[P, C]
	ExtendedX() C
	ExtendedY() C
	ExtendedZ() C
	ExtendedT() C
}

type ProjectiveCurve[P, C any] interface {
	AlgebraicCurve[P, C]
	FromProjective(x, y, z C) (P, error)
}

type ProjectivePoint[P, C any] interface {
	AlgebraicPoint[P, C]
	ProjectiveX() C
	ProjectiveY() C
	ProjectiveZ() C
}

type JacobianCurve[P, C any] interface {
	AlgebraicCurve[P, C]
	FromJacobian(x, y, z C) (P, error)
}

type JacobianPoint[P, C any] interface {
	AlgebraicPoint[P, C]
	JacobianX() C
	JacobianY() C
	JacobianZ() C
}

type EllipticCurve[P, FE, S any] interface {
	AlgebraicCurve[P, FE]
	AbelianGroup[P, S]
	AdditiveModule[P, S]
	Cofactor() Cardinal
}

type EllipticCurvePoint[P, FE, S any] interface {
	AlgebraicPoint[P, FE]
	AbelianGroupElement[P, S]
	AdditiveModuleElement[P, S]
	ClearCofactor() P
}

type PairingFriendlyCurve[P1, FE1, P2, E, S, DS any] interface {
	EllipticCurve[P1, FE1, S]
	DualStructure() DS

	PairingAlgorithm() PairingAlgorithm
	MultiPair(these []P1, duals []P2) (E, error)
	MultiPairAndInvertDuals(these []P1, duals []P2) (E, error)
}

type PairingFriendlyPoint[P1, FE1, P2, E, S any] interface {
	EllipticCurvePoint[P1, FE1, S]
	InSourceGroup() bool

	Pair(P2) (E, error)
	MultiPair(...P2) (E, error)
	MultiPairAndInvertDuals(...P2) (E, error)
}

type PairingType int

const (
	TypeI   PairingType = 1
	TypeII  PairingType = 2
	TypeIII PairingType = 3
)

type PairingProductEvaluator[g1Point, g2Point, gtElement any] interface {
	Name() PairingAlgorithm
	Type() PairingType
	Add(g1 g1Point, g2 g2Point) error
	AddAndInvG1(g1 g1Point, g2 g2Point) error
	AddAndInvG2(g1 g1Point, g2 g2Point) error
	Result() gtElement
	Check() bool
	Reset()
	base.Equatable[PairingProductEvaluator[g1Point, g2Point, gtElement]]
}
