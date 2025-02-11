package shamir

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*Share)(nil)
)

type Share struct {
	Id    types.SharingID `json:"identifier"`
	Value curves.Scalar   `json:"value"`

	_ ds.Incomparable
}

func (ss *Share) SharingId() types.SharingID {
	return ss.Id
}

func (ss *Share) Add(rhs *Share) *Share {
	return &Share{
		Id:    ss.Id,
		Value: ss.Value.Add(rhs.Value),
	}
}

func (ss *Share) AddValue(rhs curves.Scalar) *Share {
	return &Share{
		Id:    ss.Id,
		Value: ss.Value.Add(rhs),
	}
}

func (ss *Share) Sub(rhs *Share) *Share {
	return &Share{
		Id:    ss.Id,
		Value: ss.Value.Sub(rhs.Value),
	}
}

func (ss *Share) SubValue(rhs curves.Scalar) *Share {
	return &Share{
		Id:    ss.Id,
		Value: ss.Value.Sub(rhs),
	}
}

func (ss *Share) Neg() *Share {
	return &Share{
		Id:    ss.Id,
		Value: ss.Value.Neg(),
	}
}

func (ss *Share) ScalarMul(rhs curves.Scalar) *Share {
	return &Share{
		Id:    ss.Id,
		Value: ss.Value.Mul(rhs),
	}
}

func (ss *Share) Validate(curve curves.Curve) error {
	if ss.Id == 0 {
		return errs.NewValue("invalid identifier - id is zero")
	}
	if ss.Value == nil {
		return errs.NewIsNil("invalid share - value is nil")
	}

	shareCurve := ss.Value.ScalarField().Curve()
	if shareCurve.Name() != curve.Name() {
		return errs.NewCurve("curve mismatch %s != %s", shareCurve.Name(), curve.Name())
	}

	return nil
}

func (ss *Share) LagrangeCoefficient(identities []types.SharingID) (curves.Scalar, error) {
	field := ss.Value.ScalarField()
	coefficients, err := LagrangeCoefficients(field, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	return coefficients[ss.Id], nil
}

func (ss *Share) ToAdditive(identities []types.SharingID) (curves.Scalar, error) {
	lambda, err := ss.LagrangeCoefficient(identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my lagrange coefficient")
	}

	return lambda.Mul(ss.Value), nil
}

func (ss *Share) Exp() *ShareInExp {
	return &ShareInExp{
		Id:    ss.Id,
		Value: ss.Value.ScalarField().Curve().ScalarBaseMult(ss.Value),
	}
}
