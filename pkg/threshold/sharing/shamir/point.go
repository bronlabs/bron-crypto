package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*ShareInExp)(nil)
)

type ShareInExp struct {
	Id    types.SharingID `json:"identifier"`
	Value curves.Point    `json:"value"`
}

func (ps *ShareInExp) SharingId() types.SharingID {
	return ps.Id
}

func (ps *ShareInExp) Add(rhs *ShareInExp) *ShareInExp {
	return &ShareInExp{
		Id:    ps.Id,
		Value: ps.Value.Add(rhs.Value),
	}
}

func (ps *ShareInExp) AddValue(rhs curves.Point) *ShareInExp {
	return &ShareInExp{
		Id:    ps.Id,
		Value: ps.Value.Add(rhs),
	}
}

func (ps *ShareInExp) Sub(rhs *ShareInExp) *ShareInExp {
	return &ShareInExp{
		Id:    ps.Id,
		Value: ps.Value.Sub(rhs.Value),
	}
}

func (ps *ShareInExp) SubValue(rhs curves.Point) *ShareInExp {
	return &ShareInExp{
		Id:    ps.Id,
		Value: ps.Value.Sub(rhs),
	}
}

func (ps *ShareInExp) Neg() *ShareInExp {
	return &ShareInExp{
		Id:    ps.Id,
		Value: ps.Value.Neg(),
	}
}

func (ps *ShareInExp) ScalarMul(rhs curves.Scalar) *ShareInExp {
	return &ShareInExp{
		Id:    ps.Id,
		Value: ps.Value.ScalarMul(rhs),
	}
}

func (ps *ShareInExp) Validate(curve curves.Curve) error {
	if ps == nil {
		return errs.NewIsNil("receiver")
	}
	if ps.Id == 0 {
		return errs.NewValue("invalid identifier - id is zero")
	}
	if ps.Value == nil {
		return errs.NewIsNil("invalid share - value is nil")
	}

	shareCurve := ps.Value.Curve()
	if shareCurve.Name() != curve.Name() {
		return errs.NewCurve("curve mismatch %s != %s", shareCurve.Name(), curve.Name())
	}

	return nil
}
