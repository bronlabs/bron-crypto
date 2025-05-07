package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

//var (
//	_ sharing.Share = (*Share)(nil)
//)

type Share[S fields.PrimeFieldElement[S]] struct {
	Id    types.SharingID `json:"identifier"`
	Value S               `json:"value"`

	_ ds.Incomparable
}

func (ss *Share[S]) SharingId() types.SharingID {
	return ss.Id
}

func (ss *Share[S]) Add(rhs *Share[S]) *Share[S] {
	return &Share[S]{
		Id:    ss.Id,
		Value: ss.Value.Add(rhs.Value),
	}
}

func (ss *Share[S]) AddValue(rhs S) *Share[S] {
	return &Share[S]{
		Id:    ss.Id,
		Value: ss.Value.Add(rhs),
	}
}

func (ss *Share[S]) Sub(rhs *Share[S]) *Share[S] {
	return &Share[S]{
		Id:    ss.Id,
		Value: ss.Value.Sub(rhs.Value),
	}
}

func (ss *Share[S]) SubValue(rhs S) *Share[S] {
	return &Share[S]{
		Id:    ss.Id,
		Value: ss.Value.Sub(rhs),
	}
}

func (ss *Share[S]) Neg() *Share[S] {
	return &Share[S]{
		Id:    ss.Id,
		Value: ss.Value.Neg(),
	}
}

func (ss *Share[S]) ScalarMul(rhs S) *Share[S] {
	return &Share[S]{
		Id:    ss.Id,
		Value: ss.Value.Mul(rhs),
	}
}

//func (ss *Share[S]) Validate(curve curves.Curve) error {
//	if ss.Id == 0 {
//		return errs.NewValue("invalid identifier - id is zero")
//	}
//	if ss.Value == nil {
//		return errs.NewIsNil("invalid share - value is nil")
//	}
//
//	shareCurve := ss.Value.ScalarField().Curve()
//	if shareCurve.Name() != curve.Name() {
//		return errs.NewCurve("curve mismatch %s != %s", shareCurve.Name(), curve.Name())
//	}
//
//	return nil
//}

func (ss *Share[S]) LagrangeCoefficient(identities []types.SharingID) (S, error) {
	var nilS S

	field, err := fields.GetPrimeField(ss.Value)
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not get prime field")
	}

	coefficients, err := LagrangeCoefficients(field, identities)
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	return coefficients[ss.Id], nil
}

func (ss *Share[S]) ToAdditive(identities []types.SharingID) (S, error) {
	var nilS S

	lambda, err := ss.LagrangeCoefficient(identities)
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not derive my lagrange coefficient")
	}

	return lambda.Mul(ss.Value), nil
}

//func (ss *Share) Exp() *ShareInExp {
//	return &ShareInExp{
//		Id:    ss.Id,
//		Value: ss.Value.ScalarField().Curve().ScalarBaseMult(ss.Value),
//	}
//}
