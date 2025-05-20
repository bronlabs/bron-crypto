package rep23

import (
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.Share = (*IntShare)(nil)
)

type IntShare struct {
	Id   types.SharingID
	Prev *saferith.Int
	Next *saferith.Int
}

func (s *IntShare) SharingId() types.SharingID {
	return s.Id
}

func (s *IntShare) Add(rhs *IntShare) *IntShare {
	if rhs == nil || rhs.Id != s.Id {
		panic("invalid share")
	}

	return &IntShare{
		Id:   s.Id,
		Prev: new(saferith.Int).Add(s.Prev, rhs.Prev, -1),
		Next: new(saferith.Int).Add(s.Next, rhs.Next, -1),
	}
}

func (s *IntShare) AddValue(rhs *saferith.Int) *IntShare {
	switch s.SharingId() {
	case 1:
		return &IntShare{
			Id:   s.Id,
			Prev: s.Prev.Clone(),
			Next: s.Next.Clone(),
		}
	case 2:
		return &IntShare{
			Id:   s.Id,
			Prev: new(saferith.Int).Add(s.Prev, rhs, -1),
			Next: s.Next.Clone(),
		}
	case 3:
		return &IntShare{
			Id:   s.Id,
			Prev: s.Prev.Clone(),
			Next: new(saferith.Int).Add(s.Next, rhs, -1),
		}
	default:
		panic("invalid share - this should never happen")
	}
}

func (s *IntShare) Sub(rhs *IntShare) *IntShare {
	if rhs == nil || rhs.Id != s.Id {
		panic("invalid share")
	}

	return &IntShare{
		Id:   s.Id,
		Prev: new(saferith.Int).Add(s.Prev, rhs.Prev.Clone().Neg(1), -1),
		Next: new(saferith.Int).Add(s.Next, rhs.Next.Clone().Neg(1), -1),
	}
}

func (s *IntShare) SubValue(rhs *saferith.Int) *IntShare {
	switch s.SharingId() {
	case 1:
		return &IntShare{
			Id:   s.Id,
			Prev: s.Prev.Clone(),
			Next: s.Next.Clone(),
		}
	case 2:
		return &IntShare{
			Id:   s.Id,
			Prev: new(saferith.Int).Add(s.Prev, rhs.Clone().Neg(1), -1),
			Next: s.Next.Clone(),
		}
	case 3:
		return &IntShare{
			Id:   s.Id,
			Prev: s.Prev.Clone(),
			Next: new(saferith.Int).Add(s.Next, rhs.Clone().Neg(1), -1),
		}
	default:
		panic("invalid share - this should never happen")
	}
}

func (s *IntShare) Neg() *IntShare {
	return &IntShare{
		Id:   s.Id,
		Prev: s.Prev.Clone().Neg(1),
		Next: s.Next.Clone().Neg(1),
	}
}

func (s *IntShare) ScalarMul(scalar *saferith.Int) *IntShare {
	return &IntShare{
		Id:   s.Id,
		Prev: new(saferith.Int).Mul(s.Prev, scalar, -1),
		Next: new(saferith.Int).Mul(s.Next, scalar, -1),
	}
}

func (s *IntShare) ToAdditive(identities []types.SharingID) (*saferith.Int, error) {
	if len(sliceutils.Filter(identities, func(x types.SharingID) bool { return x >= 1 && x <= 3 })) < 2 {
		return nil, errs.NewFailed("not enough identities")
	}

	result := s.Next.Clone()
	if !slices.Contains(identities, nextSharingId(s.Id)) {
		result.Add(result, s.Prev, -1)
	}
	return result, nil
}

func (s *IntShare) InExponent(base *saferith.Nat, modulus *saferith.Modulus) *IntExpShare {
	prev := new(saferith.Nat).ExpI(base, s.Prev, modulus)
	next := new(saferith.Nat).ExpI(base, s.Next, modulus)
	return &IntExpShare{
		Id:   s.Id,
		Prev: prev,
		Next: next,
	}
}
