package curves

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/groups"
)

type (
	GenericCurve[P algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS], F algebra.FiniteFieldElement[F], S algebra.UintLike[S], TFP algebra.TorsionFreeEllipticCurvePoint[TFP, F, TFS], TFS algebra.PrimeFieldElement[TFS]] algebra.GenericEllipticCurve[P, F, S, TFP, TFS]
	GenericPoint[P algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS], F algebra.FiniteFieldElement[F], S algebra.UintLike[S], TFP algebra.TorsionFreeEllipticCurvePoint[TFP, F, TFS], TFS algebra.PrimeFieldElement[TFS]] algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS]

	Curve[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] algebra.TorsionFreeEllipticCurve[P, F, S]
	Point[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] algebra.TorsionFreeEllipticCurvePoint[P, F, S]

	Pairing[
		G1 Curve[G1Point, G1BaseFieldElement, G1Scalar], G1Point algebra.TorsionFreeEllipticCurvePoint[G1Point, G1BaseFieldElement, G1Scalar], G1BaseFieldElement algebra.FiniteFieldElement[G1BaseFieldElement], G1Scalar algebra.PrimeFieldElement[G1Scalar],
		G2 Curve[G2Point, G2BaseFieldElement, G2Scalar], G2Point algebra.TorsionFreeEllipticCurvePoint[G2Point, G2BaseFieldElement, G2Scalar], G2BaseFieldElement algebra.FiniteFieldElement[G2BaseFieldElement], G2Scalar algebra.PrimeFieldElement[G2Scalar],
		Gt interface {
			groups.MultiplicativeGroup[GtElement]
			groups.FiniteAbelianGroup[GtElement, GtScalar]
		}, GtElement interface {
			groups.MultiplicativeGroupElement[GtElement]
			groups.FiniteAbelianGroupElement[GtElement, GtScalar]
		}, GtScalar algebra.UintLike[GtScalar],
	] algebra.Pairing[G1, G1Point, G1BaseFieldElement, G1Scalar, G2, G2Point, G2BaseFieldElement, G2Scalar, Gt, GtElement, GtScalar]
)
