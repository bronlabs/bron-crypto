package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

type RSAGroup UnitGroup

type RSAGroupKnownOrder interface {
	RSAGroup
	KnowledgeOfOrder[*modular.OddPrimeFactors, RSAGroup]
}

func NewRSAGroup(p, q *num.NatPlus) (RSAGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, errs.NewValue("p and q must not be nil")
	}
	if p.AnnouncedLen() != q.AnnouncedLen() {
		return nil, errs.NewValue("p and q must have the same length")
	}
	if !p.IsProbablyPrime() {
		return nil, errs.NewValue("p must be prime")
	}
	if !q.IsProbablyPrime() {
		return nil, errs.NewValue("q must be prime")
	}
	zMod, err := num.NewZMod(p.Mul(q))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	exp, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, errs.NewValue("failed to create OddPrimeFactors")
	}
	return &rsaGroupKnownOrder{
		rsaGroup: rsaGroup{
			zMod:  zMod,
			order: cardinal.Unknown(),
			arith: exp,
		},
	}, nil
}

func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (RSAGroup, error) {
	out, err := NewUnitGroupOfUnknownOrder[*modular.OddPrimeFactors](m)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type rsaGroup = UZMod[*modular.OddPrimeFactors]

type rsaGroupKnownOrder struct {
	rsaGroup
}

func (rg *rsaGroupKnownOrder) Arithmetic() *modular.OddPrimeFactors {
	return rg.arith
}

func (rg *rsaGroupKnownOrder) ForgetOrder() RSAGroup {
	return &rsaGroup{
		zMod:  rg.zMod,
		order: cardinal.Unknown(),
		arith: new(modular.OddPrimeFactors),
	}
}
