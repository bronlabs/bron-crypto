package replicated

import (
	"io"

	"golang.org/x/exp/maps"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var (
	_ Expression = (*Party)(nil)
	_ Expression = (*andExpression)(nil)
	_ Expression = (*orExpression)(nil)
)

type SharindIdSet uint64

func (s *SharindIdSet) Contains(value types.SharingID) bool {
	if value < 1 || value > 64 {
		panic("value out of range")
	}

	return (*s & (1 << (value - 1))) != 0
}

type Expression interface {
	MaxId() types.SharingID
	Eval(bitSet SharindIdSet) bool
	And(rhs Expression) Expression
	Or(rhs Expression) Expression
}

type Share struct {
	Id        types.SharingID
	SubShares map[SharindIdSet]curves.Scalar
}

type Party struct {
	id types.SharingID
}

func PartyNew(id types.SharingID) *Party {
	return &Party{id: id}
}

func (p *Party) Eval(bitSet SharindIdSet) bool {
	return bitSet.Contains(p.id)
}

func (p *Party) And(rhs Expression) Expression {
	return &andExpression{
		l: p,
		r: rhs,
	}
}

func (p *Party) Or(rhs Expression) Expression {
	return &orExpression{
		l: p,
		r: rhs,
	}
}

func (p *Party) Id() types.SharingID {
	return p.id
}

func (p *Party) MaxId() types.SharingID {
	return p.Id()
}

type andExpression struct {
	l, r Expression
}

func (x *andExpression) Eval(bitSet SharindIdSet) bool {
	return x.l.Eval(bitSet) && x.r.Eval(bitSet)
}

func (x *andExpression) And(rhs Expression) Expression {
	return &andExpression{
		l: x,
		r: rhs,
	}
}

func (x *andExpression) Or(rhs Expression) Expression {
	return &orExpression{
		l: x,
		r: rhs,
	}
}

func (x *andExpression) MaxId() types.SharingID {
	return max(x.l.MaxId(), x.r.MaxId())
}

type orExpression struct {
	l, r Expression
}

func (x *orExpression) Eval(bitSet SharindIdSet) bool {
	return x.l.Eval(bitSet) || x.r.Eval(bitSet)
}

func (x *orExpression) And(rhs Expression) Expression {
	return &andExpression{
		l: x,
		r: rhs,
	}
}

func (x *orExpression) Or(rhs Expression) Expression {
	return &orExpression{
		l: x,
		r: rhs,
	}
}

func (x *orExpression) MaxId() types.SharingID {
	return max(x.l.MaxId(), x.r.MaxId())
}

type AccessStructure struct {
	maxSharingId    types.SharingID
	unqualifiedSets []SharindIdSet
}

func AccessStructureNew(expr Expression) *AccessStructure {
	unqualifiedSets := []SharindIdSet{}
	for i := 1; i < (1 << expr.MaxId()); i++ {
		if !expr.Eval(SharindIdSet(i)) {
			unqualifiedSets = append(unqualifiedSets, SharindIdSet(i))
		}
	}

	return &AccessStructure{
		maxSharingId:    expr.MaxId(),
		unqualifiedSets: unqualifiedSets,
	}
}

func (as *AccessStructure) Share(value curves.Scalar, prng io.Reader) ([]*Share, error) {
	subShares := make([]curves.Scalar, len(as.unqualifiedSets))
	sum := value.ScalarField().AdditiveIdentity()
	for i := 1; i < len(subShares); i++ {
		var err error
		subShares[i], err = value.ScalarField().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot sample random")
		}
		sum = sum.Add(subShares[i])
	}
	subShares[0] = value.Sub(sum)

	subSharesMap := make(map[SharindIdSet]curves.Scalar)
	i := 0
	for _, set := range as.unqualifiedSets {
		subSharesMap[set] = subShares[i]
		i++
	}

	shares := make([]*Share, as.maxSharingId)
	for j := range shares {
		id := types.SharingID(j + 1)
		shares[j] = &Share{
			Id:        id,
			SubShares: make(map[SharindIdSet]curves.Scalar),
		}
		for _, unqualifiedSet := range as.unqualifiedSets {
			if !unqualifiedSet.Contains(id) {
				shares[j].SubShares[unqualifiedSet] = subSharesMap[unqualifiedSet]
			}
		}
	}

	return shares, nil
}

func (as *AccessStructure) Combine(shares ...*Share) (curves.Scalar, error) {
	subSharesMap := make(map[SharindIdSet]curves.Scalar)
	for _, share := range shares {
		for unqualifiedSet, subShare := range share.SubShares {
			if old, contains := subSharesMap[unqualifiedSet]; contains {
				if !old.Equal(subShare) {
					return nil, errs.NewFailed("invalid share")
				}
			} else {
				subSharesMap[unqualifiedSet] = subShare
			}
		}
	}

	// check if reconstruction is possible
	for _, unqualifiedSet := range as.unqualifiedSets {
		if _, contains := subSharesMap[unqualifiedSet]; !contains {
			return nil, errs.NewFailed("not enough sub-shares")
		}
	}

	secret := maps.Values(shares[0].SubShares)[0].ScalarField().AdditiveIdentity()
	for _, subShare := range subSharesMap {
		secret = secret.Add(subShare)
	}

	return secret, nil
}
