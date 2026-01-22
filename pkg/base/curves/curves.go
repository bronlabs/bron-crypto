package curves

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type (
	EllipticCurve[P ECPoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.UintLike[S]] interface {
		algebra.EllipticCurve[P, F, S]
		PrimeSubGroupGenerator() P

		ScalarRing() algebra.ZModLike[S]
		BaseField() algebra.FiniteField[F]
	}
	ECPoint[P algebra.EllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.UintLike[S]] interface {
		algebra.EllipticCurvePoint[P, F, S]
		IsPrimeSubGroupDesignatedGenerator() bool
	}

	Curve[P Point[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] interface {
		EllipticCurve[P, F, S]
		algebra.PrimeOrderEllipticCurve[P, F, S]
		HashWithDst(dst string, message []byte) (P, error)
		algebra.FiniteStructure[P]

		ScalarField() algebra.PrimeField[S]
	}

	Point[P algebra.EllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] interface {
		algebra.PrimeOrderEllipticCurvePoint[P, F, S]
		ECPoint[P, F, S]
	}

	PairingFriendlyCurve[
		P1 PairingFriendlyPoint[P1, F1, P2, F2, E, S], F1 algebra.FiniteFieldElement[F1],
		P2 PairingFriendlyPoint[P2, F2, P1, F1, E, S], F2 algebra.FiniteFieldElement[F2],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] interface {
		algebra.PairingFriendlyCurve[P1, F1, P2, F2, E, S, PairingFriendlyCurve[P2, F2, P1, F1, E, S]]
		Curve[P1, F1, S]
	}

	PairingFriendlyPoint[
		P1 algebra.PairingFriendlyPoint[P1, F1, P2, F2, E, S], F1 algebra.FiniteFieldElement[F1],
		P2 algebra.PairingFriendlyPoint[P2, F2, P1, F1, E, S], F2 algebra.FiniteFieldElement[F2],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] interface {
		algebra.PairingFriendlyPoint[P1, F1, P2, F2, E, S]
		Point[P1, F1, S]
	}

	PairingFriendlyFamily[
		P1 PairingFriendlyPoint[P1, F1, P2, F2, E, S], F1 algebra.FiniteFieldElement[F1],
		P2 PairingFriendlyPoint[P2, F2, P1, F1, E, S], F2 algebra.FiniteFieldElement[F2],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] interface {
		Name() string
		SourceSubGroup() PairingFriendlyCurve[P1, F1, P2, F2, E, S]
		TwistedSubGroup() PairingFriendlyCurve[P2, F2, P1, F1, E, S]
		TargetSubGroup() algebra.MultiplicativeGroup[E]
		GetPPE(PairingAlgorithm) (out PPE[P1, F1, P2, F2, E, S], exists bool)
	}

	PairingType      = algebra.PairingType
	PairingAlgorithm = algebra.PairingName

	PPE[
		P1 PairingFriendlyPoint[P1, F1, P2, F2, E, S], F1 algebra.FiniteFieldElement[F1],
		P2 PairingFriendlyPoint[P2, F2, P1, F1, E, S], F2 algebra.FiniteFieldElement[F2],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = algebra.PairingProductEvaluator[P1, F1, P2, F2, E, S]
)

const (
	// TypeI is a symmetric pairing type.
	TypeI = algebra.TypeI
	// TypeII is an asymmetric pairing type with homomorphism.
	TypeII = algebra.TypeII
	// TypeIII is an asymmetric pairing type without homomorphism.
	TypeIII = algebra.TypeIII
)
