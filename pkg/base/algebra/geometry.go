package algebra

import "github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"

type (
	CoordinateSystem                   = crtp.CoordinateSystem
	Coordinates[C crtp.RingElement[C]] = crtp.Coordinates[C]

	Variety[E crtp.RationalPoint[E, C], C crtp.RingElement[C]]       crtp.Variety[E, C]
	RationalPoint[E crtp.RationalPoint[E, C], C crtp.RingElement[C]] crtp.RationalPoint[E, C]

	AlgebraicCurve[P crtp.AlgebraicPoint[P, C], C crtp.RingElement[C]] crtp.AlgebraicCurve[P, C]
	AlgebraicPoint[P crtp.AlgebraicPoint[P, C], C crtp.RingElement[C]] crtp.AlgebraicPoint[P, C]

	AffineCurve[P crtp.AffinePoint[P, C], C crtp.RingElement[C]] crtp.AffineCurve[P, C]
	AffinePoint[P crtp.AffinePoint[P, C], C crtp.RingElement[C]] crtp.AffinePoint[P, C]

	ExtendedHomogeneousCurve[P crtp.ExtendedHomogeneousPoint[P, C], C crtp.RingElement[C]] crtp.ExtendedHomogeneousCurve[P, C]
	ExtendedHomogeneousPoint[P crtp.ExtendedHomogeneousPoint[P, C], C crtp.RingElement[C]] crtp.ExtendedHomogeneousPoint[P, C]

	ProjectiveCurve[P crtp.ProjectivePoint[P, C], C crtp.RingElement[C]] crtp.ProjectiveCurve[P, C]
	ProjectivePoint[P crtp.ProjectivePoint[P, C], C crtp.RingElement[C]] crtp.ProjectivePoint[P, C]

	JacobianCurve[P crtp.JacobianPoint[P, C], C crtp.RingElement[C]] crtp.JacobianCurve[P, C]
	JacobianPoint[P crtp.JacobianPoint[P, C], C crtp.RingElement[C]] crtp.JacobianPoint[P, C]

	EllipticCurve[P crtp.EllipticCurvePoint[P, B, S], B crtp.FieldElement[B], S crtp.UintLike[S]]      crtp.EllipticCurve[P, B, S]
	EllipticCurvePoint[P crtp.EllipticCurvePoint[P, B, S], B crtp.FieldElement[B], S crtp.UintLike[S]] crtp.EllipticCurvePoint[P, B, S]

	PrimeOrderEllipticCurve[P crtp.EllipticCurvePoint[P, B, S], B crtp.FieldElement[B], S crtp.PrimeFieldElement[S]] interface {
		crtp.EllipticCurve[P, B, S]
		crtp.AdditivePrimeGroup[P, S]
	}
	PrimeOrderEllipticCurvePoint[P crtp.EllipticCurvePoint[P, B, S], B crtp.FieldElement[B], S crtp.PrimeFieldElement[S]] interface {
		crtp.EllipticCurvePoint[P, B, S]
		crtp.AdditivePrimeGroupElement[P, S]
	}

	PairingFriendlyCurve[
		P1 PairingFriendlyPoint[P1, B1, P2, B2, E, S], B1 crtp.FieldElement[B1],
		P2 PairingFriendlyPoint[P2, B2, P1, B1, E, S], B2 crtp.FieldElement[B2],
		E crtp.MultiplicativeGroupElement[E], S crtp.PrimeFieldElement[S], DualStructureType any,
	] interface {
		crtp.PairingFriendlyCurve[P1, B1, P2, E, S, DualStructureType]
		PrimeOrderEllipticCurve[P1, B1, S]
	}

	PairingFriendlyPoint[
		P1 crtp.PairingFriendlyPoint[P1, B1, P2, E, S], B1 crtp.FieldElement[B1],
		P2 crtp.PairingFriendlyPoint[P2, B2, P1, E, S], B2 crtp.FieldElement[B2],
		E crtp.MultiplicativeGroupElement[E], S crtp.PrimeFieldElement[S],
	] interface {
		crtp.PairingFriendlyPoint[P1, B1, P2, E, S]
		PrimeOrderEllipticCurvePoint[P1, B1, S]
	}

	PairingName = crtp.PairingAlgorithm
	PairingType = crtp.PairingType

	PairingProductEvaluator[
		P1 PairingFriendlyPoint[P1, B1, P2, B2, E, S], B1 crtp.FieldElement[B1],
		P2 PairingFriendlyPoint[P2, B2, P1, B1, E, S], B2 crtp.FieldElement[B2],
		E crtp.MultiplicativeGroupElement[E], S crtp.PrimeFieldElement[S],
	] = crtp.PairingProductEvaluator[P1, P2, E]
)

const (
	AffineCoordinateSystem              = crtp.AffineCoordinateSystem
	ExtendedHomogeneousCoordinateSystem = crtp.ExtendedHomogeneousCoordinateSystem
	ProjectiveCoordinateSystem          = crtp.ProjectiveCoordinateSystem
	JacobianCoordinateSystem            = crtp.JacobianCoordinateSystem

	TypeI   = crtp.TypeI
	TypeII  = crtp.TypeII
	TypeIII = crtp.TypeIII
)
