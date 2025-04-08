package curves

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	GenericCurve[P algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS], F algebra.FiniteFieldElement[F], S algebra.UintLike[S], TFP algebra.TorsionFreeEllipticCurvePoint[TFP, F, TFS], TFS algebra.PrimeFieldElement[TFS]] algebra.GenericEllipticCurve[P, F, S, TFP, TFS]
	GenericPoint[P algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS], F algebra.FiniteFieldElement[F], S algebra.UintLike[S], TFP algebra.TorsionFreeEllipticCurvePoint[TFP, F, TFS], TFS algebra.PrimeFieldElement[TFS]] algebra.GenericEllipticCurvePoint[P, F, S, TFP, TFS]

	Curve[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] algebra.TorsionFreeEllipticCurve[P, F, S]
	Point[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]] algebra.TorsionFreeEllipticCurvePoint[P, F, S]

	PairingFriendlyCurve[P algebra.TorsionFreeEllipticCurvePoint[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S], P2 algebra.TorsionFreeEllipticCurvePoint[P2, F2, S], F2 algebra.FiniteFieldElement[F2]] algebra.PairingFriendlyCurve[P, F, S, P2, F2]

	Pairing[
		G1 Curve[G1Point, G1BaseFieldElement, Scalar], G1Point algebra.TorsionFreeEllipticCurvePoint[G1Point, G1BaseFieldElement, Scalar], G1BaseFieldElement algebra.FiniteFieldElement[G1BaseFieldElement],
		G2 Curve[G2Point, G2BaseFieldElement, Scalar], G2Point algebra.TorsionFreeEllipticCurvePoint[G2Point, G2BaseFieldElement, Scalar], G2BaseFieldElement algebra.FiniteFieldElement[G2BaseFieldElement],
		Gt interface {
			groups.MultiplicativeGroup[GtElement]
			groups.FiniteAbelianGroup[GtElement, Scalar]
		}, GtElement interface {
			groups.MultiplicativeGroupElement[GtElement]
			groups.FiniteAbelianGroupElement[GtElement, Scalar]
		}, Scalar fields.PrimeFieldElement[Scalar],
	] algebra.Pairing[G1, G1Point, G1BaseFieldElement, G2, G2Point, G2BaseFieldElement, Gt, GtElement, Scalar]
)

func GetCurve[P Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](p P) (Curve[P, F, S], error) {
	f, ok := p.Structure().(Curve[P, F, S])
	if !ok {
		return nil, errs.NewType("FieldElement does not have a Field structure")
	}
	return f, nil
}

func GetPointScalarField[P Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](p P) (fields.PrimeField[S], error) {
	c, ok := p.Structure().(Curve[P, F, S])
	if !ok {
		return nil, errs.NewType("PointTrait does not have a CurveTrait structure")
	}
	sf, ok := c.ScalarField().(fields.PrimeField[S])
	if !ok {
		return nil, errs.NewType("ScalarField is not CurveTrait's ScalarField")
	}

	return sf, nil
}
