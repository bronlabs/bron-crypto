package intshamir

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*IntShare)(nil)
)

type IntShare struct {
	Id    types.SharingID
	Value *saferith.Int
}

func (s *IntShare) SharingId() types.SharingID {
	return s.Id
}

func (s *IntShare) Add(rhs *IntShare) *IntShare {
	if rhs == nil || s.Id != rhs.Id {
		panic("invalid sharing id")
	}

	result := &IntShare{
		Id:    s.Id,
		Value: new(saferith.Int).Add(s.Value, rhs.Value, -1),
	}
	return result
}

func (s *IntShare) AddValue(rhs *saferith.Int) *IntShare {
	if rhs == nil {
		panic("rhs is nil")
	}

	result := &IntShare{
		Id:    s.Id,
		Value: new(saferith.Int).Add(s.Value, rhs, -1),
	}
	return result
}

func (s *IntShare) Sub(rhs *IntShare) *IntShare {
	if rhs == nil || s.Id != rhs.Id {
		panic("invalid sharing id")
	}

	result := &IntShare{
		Id:    s.Id,
		Value: new(saferith.Int).Add(s.Value, rhs.Value.Clone().Neg(1), -1),
	}
	return result
}

func (s *IntShare) SubValue(rhs *saferith.Int) *IntShare {
	if rhs == nil {
		panic("rhs is nil")
	}

	result := &IntShare{
		Id:    s.Id,
		Value: new(saferith.Int).Add(s.Value, rhs.Clone().Neg(1), -1),
	}
	return result
}

func (s *IntShare) Neg() *IntShare {
	result := &IntShare{
		Id:    s.Id,
		Value: s.Value.Clone().Neg(1),
	}
	return result
}

func (s *IntShare) MulScalar(rhs *saferith.Int) *IntShare {
	if rhs == nil {
		panic("rhs is nil")
	}

	result := &IntShare{
		Id:    s.Id,
		Value: new(saferith.Int).Mul(s.Value, rhs, -1),
	}
	return result
}
