package rep23

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var _ sharing.LinearScheme[*IntShare, *saferith.Int, *saferith.Int] = (*IntScheme)(nil)

type IntScheme struct {
}

func NewIntScheme() *IntScheme {
	return &IntScheme{}
}

func (*IntScheme) Deal(secret *saferith.Int, prng io.Reader) (shares map[types.SharingID]*IntShare, err error) {
	bitLen := secret.AnnouncedLen() + base.ComputationalSecurity
	bound := new(big.Int)
	bound = bound.SetBit(bound, bitLen, 1)
	mid := new(big.Int)
	mid = mid.SetBit(mid, bitLen-1, 1)

	s1, err := crand.Int(prng, bound)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random number")
	}
	s1.Sub(s1, mid)

	s2, err := crand.Int(prng, bound)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random number")
	}
	s2.Sub(s2, mid)

	s3 := new(big.Int).Sub(secret.Big(), s1)
	s3 = s3.Sub(s3, s2)

	return map[types.SharingID]*IntShare{
		1: {
			Id:   1,
			Prev: new(saferith.Int).SetBig(s3, s3.BitLen()),
			Next: new(saferith.Int).SetBig(s2, s2.BitLen()),
		},
		2: {
			Id:   2,
			Prev: new(saferith.Int).SetBig(s1, s1.BitLen()),
			Next: new(saferith.Int).SetBig(s3, s3.BitLen()),
		},
		3: {
			Id:   3,
			Prev: new(saferith.Int).SetBig(s2, s2.BitLen()),
			Next: new(saferith.Int).SetBig(s1, s1.BitLen()),
		},
	}, nil
}

func (*IntScheme) Open(shares ...*IntShare) (secret *saferith.Int, err error) {
	subShares := make(map[types.SharingID]*saferith.Int)
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

	secret = new(saferith.Int)
	for _, subShare := range subShares {
		secret.Add(secret, subShare, -1)
	}
	return secret, nil
}

func (*IntScheme) ShareAdd(lhs, rhs *IntShare) *IntShare {
	return lhs.Add(rhs)
}

func (*IntScheme) ShareAddValue(lhs *IntShare, rhs *saferith.Int) *IntShare {
	return lhs.AddValue(rhs)
}

func (*IntScheme) ShareSub(lhs, rhs *IntShare) *IntShare {
	return lhs.Sub(rhs)
}

func (*IntScheme) ShareSubValue(lhs *IntShare, rhs *saferith.Int) *IntShare {
	return lhs.SubValue(rhs)
}

func (*IntScheme) ShareNeg(lhs *IntShare) *IntShare {
	return lhs.Neg()
}

func (*IntScheme) ShareMul(lhs *IntShare, rhs *saferith.Int) *IntShare {
	return lhs.ScalarMul(rhs)
}
