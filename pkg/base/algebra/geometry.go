package algebra

import aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"

type (
	CoordinateSystem                    = aimpl.CoordinateSystem
	Coordinates[C aimpl.RingElement[C]] = aimpl.Coordinates[C]

	Variety[E aimpl.RationalPoint[E, C], C aimpl.RingElement[C]]       aimpl.Variety[E, C]
	RationalPoint[E aimpl.RationalPoint[E, C], C aimpl.RingElement[C]] aimpl.RationalPoint[E, C]

	AlgebraicCurve[P aimpl.AlgebraicPoint[P, C], C aimpl.RingElement[C]] aimpl.AlgebraicCurve[P, C]
	AlgebraicPoint[P aimpl.AlgebraicPoint[P, C], C aimpl.RingElement[C]] aimpl.AlgebraicPoint[P, C]

	AffineCurve[P aimpl.AffinePoint[P, C], C aimpl.RingElement[C]] aimpl.AffineCurve[P, C]
	AffinePoint[P aimpl.AffinePoint[P, C], C aimpl.RingElement[C]] aimpl.AffinePoint[P, C]

	ExtendedHomogeneousCurve[P aimpl.ExtendedHomogeneousPoint[P, C], C aimpl.RingElement[C]] aimpl.ExtendedHomogeneousCurve[P, C]
	ExtendedHomogeneousPoint[P aimpl.ExtendedHomogeneousPoint[P, C], C aimpl.RingElement[C]] aimpl.ExtendedHomogeneousPoint[P, C]

	ProjectiveCurve[P aimpl.ProjectivePoint[P, C], C aimpl.RingElement[C]] aimpl.ProjectiveCurve[P, C]
	ProjectivePoint[P aimpl.ProjectivePoint[P, C], C aimpl.RingElement[C]] aimpl.ProjectivePoint[P, C]

	JacobianCurve[P aimpl.JacobianPoint[P, C], C aimpl.RingElement[C]] aimpl.JacobianCurve[P, C]
	JacobianPoint[P aimpl.JacobianPoint[P, C], C aimpl.RingElement[C]] aimpl.JacobianPoint[P, C]

	EllipticCurve[P aimpl.EllipticCurvePoint[P, B, S], B aimpl.FiniteFieldElement[B], S aimpl.UintLike[S]]      aimpl.EllipticCurve[P, B, S]
	EllipticCurvePoint[P aimpl.EllipticCurvePoint[P, B, S], B aimpl.FiniteFieldElement[B], S aimpl.UintLike[S]] aimpl.EllipticCurvePoint[P, B, S]

	PrimeOrderEllipticCurve[P aimpl.EllipticCurvePoint[P, B, S], B aimpl.FiniteFieldElement[B], S aimpl.PrimeFieldElement[S]] interface {
		aimpl.EllipticCurve[P, B, S]
		aimpl.AdditivePrimeGroup[P, S]
	}
	PrimeOrderEllipticCurvePoint[P aimpl.EllipticCurvePoint[P, B, S], B aimpl.FiniteFieldElement[B], S aimpl.PrimeFieldElement[S]] interface {
		aimpl.EllipticCurvePoint[P, B, S]
		aimpl.AdditivePrimeGroupElement[P, S]
	}

	PairingFriendlyCurve[
		P1 PairingFriendlyPoint[P1, B1, P2, B2, E, S], B1 aimpl.FiniteFieldElement[B1],
		P2 PairingFriendlyPoint[P2, B2, P1, B1, E, S], B2 aimpl.FiniteFieldElement[B2],
		E aimpl.MultiplicativeGroupElement[E], S aimpl.PrimeFieldElement[S], DualStructureType any,
	] interface {
		aimpl.PairingFriendlyCurve[P1, B1, P2, E, S, DualStructureType]
		PrimeOrderEllipticCurve[P1, B1, S]
	}

	PairingFriendlyPoint[
		P1 aimpl.PairingFriendlyPoint[P1, B1, P2, E, S], B1 aimpl.FiniteFieldElement[B1],
		P2 aimpl.PairingFriendlyPoint[P2, B2, P1, E, S], B2 aimpl.FiniteFieldElement[B2],
		E aimpl.MultiplicativeGroupElement[E], S aimpl.PrimeFieldElement[S],
	] interface {
		aimpl.PairingFriendlyPoint[P1, B1, P2, E, S]
		PrimeOrderEllipticCurvePoint[P1, B1, S]
	}

	PairingName = aimpl.PairingAlgorithm
	PairingType = aimpl.PairingType

	PairingProductEvaluator[
		P1 PairingFriendlyPoint[P1, B1, P2, B2, E, S], B1 aimpl.FiniteFieldElement[B1],
		P2 PairingFriendlyPoint[P2, B2, P1, B1, E, S], B2 aimpl.FiniteFieldElement[B2],
		E aimpl.MultiplicativeGroupElement[E], S aimpl.PrimeFieldElement[S],
	] = aimpl.PairingProductEvaluator[P1, P2, E]
)

const (
	AffineCoordinateSystem              = aimpl.AffineCoordinateSystem
	ExtendedHomogeneousCoordinateSystem = aimpl.ExtendedHomogeneousCoordinateSystem
	ProjectiveCoordinateSystem          = aimpl.ProjectiveCoordinateSystem
	JacobianCoordinateSystem            = aimpl.JacobianCoordinateSystem

	TypeI   = aimpl.TypeI
	TypeII  = aimpl.TypeII
	TypeIII = aimpl.TypeIII
)
