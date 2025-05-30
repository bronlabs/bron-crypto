package rep23

import (
	crand "crypto/rand"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var _ sharing.LinearScheme[*IntExpShare, *saferith.Nat, *saferith.Int] = (*IntExpScheme)(nil)

type IntExpScheme struct {
	Scheme  *IntScheme
	Modulus *saferith.Modulus
}

func NewIntExpScheme(modulus *saferith.Modulus) *IntExpScheme {
	return &IntExpScheme{
		Scheme:  NewIntScheme(),
		Modulus: modulus,
	}
}

func (s *IntExpScheme) Deal(secret *saferith.Nat, prng io.Reader) (shares map[types.SharingID]*IntExpShare, err error) {
	s1, err := crand.Int(prng, s.Modulus.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random number")
	}
	s1Nat := new(saferith.Nat).SetBig(s1, s.Modulus.BitLen())

	s2, err := crand.Int(prng, s.Modulus.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random number")
	}
	s2Nat := new(saferith.Nat).SetBig(s2, s.Modulus.BitLen())

	s3Nat := new(saferith.Nat).ModMul(s1Nat, s2Nat, s.Modulus)
	s3Nat.ModInverse(s3Nat, s.Modulus)
	s3Nat.ModMul(s3Nat, secret, s.Modulus)

	return map[types.SharingID]*IntExpShare{
		1: {
			Id:   1,
			Prev: s3Nat.Clone(),
			Next: s2Nat.Clone(),
		},
		2: {
			Id:   2,
			Prev: s1Nat.Clone(),
			Next: s3Nat.Clone(),
		},
		3: {
			Id:   3,
			Prev: s2Nat.Clone(),
			Next: s1Nat.Clone(),
		},
	}, nil
}

func (s *IntExpScheme) Open(shares ...*IntExpShare) (secret *saferith.Nat, err error) {
	subShares := make(map[types.SharingID]*saferith.Nat)
	for _, share := range shares {
		prevId := prevSharingId(share.Id)
		oldPrev, okPrev := subShares[prevId]
		if !okPrev {
			subShares[prevId] = share.Prev
		} else if oldPrev.Eq(share.Prev) == 0 {
			return nil, errs.NewFailed("invalid shares")
		}
		nextId := nextSharingId(share.Id)
		oldNext, okNext := subShares[nextId]
		if !okNext {
			subShares[nextId] = share.Next
		} else if oldNext.Eq(share.Next) == 0 {
			return nil, errs.NewFailed("invalid shares")
		}
	}

	if len(subShares) != 3 {
		return nil, errs.NewFailed("invalid shares")
	}

	secret = new(saferith.Nat).SetUint64(1)
	for _, subShare := range subShares {
		secret.ModMul(secret, subShare, s.Modulus)
	}
	return secret, nil
}

func (s *IntExpScheme) ShareAdd(lhs, rhs *IntExpShare) *IntExpShare {
	return &IntExpShare{
		Id:   lhs.Id,
		Prev: new(saferith.Nat).ModMul(lhs.Prev, rhs.Prev, s.Modulus),
		Next: new(saferith.Nat).ModMul(lhs.Next, rhs.Next, s.Modulus),
	}
}

func (s *IntExpScheme) ShareAddValue(lhs *IntExpShare, rhs *saferith.Nat) *IntExpShare {
	switch lhs.Id {
	case 1:
		return &IntExpShare{
			Id:   lhs.Id,
			Prev: lhs.Prev.Clone(),
			Next: lhs.Next.Clone(),
		}
	case 2:
		return &IntExpShare{
			Id:   lhs.Id,
			Prev: new(saferith.Nat).ModMul(lhs.Prev, rhs, s.Modulus),
			Next: lhs.Next.Clone(),
		}
	case 3:
		return &IntExpShare{
			Id:   lhs.Id,
			Prev: lhs.Prev.Clone(),
			Next: new(saferith.Nat).ModMul(lhs.Next, rhs, s.Modulus),
		}
	}

	panic("invalid share - this should never happen")
}

func (s *IntExpScheme) ShareSub(lhs, rhs *IntExpShare) *IntExpShare {
	return s.ShareAdd(lhs, s.ShareNeg(rhs))
}

func (s *IntExpScheme) ShareSubValue(lhs *IntExpShare, rhs *saferith.Nat) *IntExpShare {
	rhsInv := new(saferith.Nat).ModInverse(rhs, s.Modulus)
	return s.ShareAddValue(lhs, rhsInv)
}

func (s *IntExpScheme) ShareNeg(lhs *IntExpShare) *IntExpShare {
	return &IntExpShare{
		Id:   lhs.Id,
		Prev: new(saferith.Nat).ModInverse(lhs.Prev, s.Modulus),
		Next: new(saferith.Nat).ModInverse(lhs.Next, s.Modulus),
	}
}

func (s *IntExpScheme) ShareMul(lhs *IntExpShare, rhs *saferith.Int) *IntExpShare {
	return &IntExpShare{
		Id:   lhs.Id,
		Prev: new(saferith.Nat).ExpI(lhs.Prev, rhs, s.Modulus),
		Next: new(saferith.Nat).ExpI(lhs.Next, rhs, s.Modulus),
	}
}
