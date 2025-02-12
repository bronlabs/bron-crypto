package additive

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*Share)(nil)
)

type Share struct {
	Id    types.SharingID `json:"id"`
	Value curves.Scalar   `json:"value"`

	_ ds.Incomparable
}

func (s *Share) Add(rhs *Share) *Share {
	return &Share{
		Id:    s.Id,
		Value: s.Value.Add(rhs.Value),
	}
}

func (s *Share) AddValue(rhs curves.Scalar) *Share {
	if s.Id == 1 {
		return &Share{
			Id:    s.Id,
			Value: s.Value.Add(rhs),
		}
	} else {
		return &Share{
			Id:    s.Id,
			Value: s.Value.Clone(),
		}
	}
}

func (s *Share) Sub(rhs *Share) *Share {
	return &Share{
		Id:    s.Id,
		Value: s.Value.Sub(rhs.Value),
	}
}

func (s *Share) SubValue(rhs curves.Scalar) *Share {
	if s.Id == 1 {
		return &Share{
			Id:    s.Id,
			Value: s.Value.Sub(rhs),
		}
	} else {
		return &Share{
			Id:    s.Id,
			Value: s.Value.Clone(),
		}
	}
}

func (s *Share) Neg() *Share {
	return &Share{
		Id:    s.Id,
		Value: s.Value.Neg(),
	}
}

func (s *Share) ScalarMul(rhs curves.Scalar) *Share {
	return &Share{
		Id:    s.Id,
		Value: s.Value.Mul(rhs),
	}
}

func (s *Share) SharingId() types.SharingID {
	return s.Id
}

func (s *Share) Exp() *ShareInExp {
	return &ShareInExp{
		Id:    s.Id,
		Value: s.Value.ScalarField().Curve().ScalarBaseMult(s.Value),
	}
}
