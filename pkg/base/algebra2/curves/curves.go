package curves

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
)

type (
	GenericCurve[P algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS], F algebra.FiniteFieldElement[F], S algebra.UintLike[S], TFP algebra.TorsionFreeEllipticCurvePoint[TFP, F, TFS], TFS algebra.PrimeFieldElement[TFS]] algebra.GenericEllipticCurve[P, F, S, TFP, TFS]
	GenericPoint[P algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS], F algebra.FiniteFieldElement[F], S algebra.UintLike[S], TFP algebra.TorsionFreeEllipticCurvePoint[TFP, F, TFS], TFS algebra.PrimeFieldElement[TFS]] algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS]

	TorsionFreeCurve[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] algebra.TorsionFreeEllipticCurve[P, F, S]
	TorsionFreePoint[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] algebra.TorsionFreeEllipticCurvePoint[P, F, S]

	Curve[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] = TorsionFreeCurve[P, F, S]
	Point[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] = TorsionFreePoint[P, F, S]
)
