package additive

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*ShareInExp)(nil)
)

type ShareInExp struct {
	Id    types.SharingID `json:"id"`
	Value curves.Point    `json:"value"`

	_ ds.Incomparable
}

func (s *ShareInExp) Add(rhs *ShareInExp) *ShareInExp {
	return &ShareInExp{
		Id:    s.Id,
		Value: s.Value.Add(rhs.Value),
	}
}

func (s *ShareInExp) AddValue(rhs curves.Point) *ShareInExp {
	if s.Id == 1 {
		return &ShareInExp{
			Id:    s.Id,
			Value: s.Value.Add(rhs),
		}
	} else {
		return &ShareInExp{
			Id:    s.Id,
			Value: s.Value.Clone(),
		}
	}
}

func (s *ShareInExp) Sub(rhs *ShareInExp) *ShareInExp {
	return &ShareInExp{
		Id:    s.Id,
		Value: s.Value.Sub(rhs.Value),
	}
}

func (s *ShareInExp) SubValue(rhs curves.Point) *ShareInExp {
	if s.Id == 1 {
		return &ShareInExp{
			Id:    s.Id,
			Value: s.Value.Sub(rhs),
		}
	} else {
		return &ShareInExp{
			Id:    s.Id,
			Value: s.Value.Clone(),
		}
	}
}

func (s *ShareInExp) Neg() *ShareInExp {
	return &ShareInExp{
		Id:    s.Id,
		Value: s.Value.Neg(),
	}
}

func (s *ShareInExp) ScalarMul(rhs curves.Scalar) *ShareInExp {
	return &ShareInExp{
		Id:    s.Id,
		Value: s.Value.ScalarMul(rhs),
	}
}

func (s *ShareInExp) SharingId() types.SharingID {
	return s.Id
}
