package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar/internal"
)

type rsaGroupUnknownOrder struct {
	internal.UnitGroupTrait[*rsaGroupUnknownOrder, *rsaUnitUnknownOrder, *rsaUnitUnknownOrder, rsaUnitUnknownOrder]
}

type rsaGroupKnownOrder struct {
	internal.UnitGroupTrait[*rsaGroupKnownOrder, *rsaUnitUnioned[*rsaUnitKnownOrder], *rsaUnitKnownOrder, rsaUnitKnownOrder]
	p     *num.NatPlus
	q     *num.NatPlus
	arith *modular.OddPrimeFactors
}

func (g *rsaGroupKnownOrder) FromBytes(b []byte) (RSAUnit, error) {
	out, err := g.UnitGroupTrait.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (g *rsaGroupKnownOrder) Clone() RSAUnit {
	out := g.UnitGroupTrait.Clone()
	return out
}

func (g *rsaGroupKnownOrder) ForgetOrder() RSAGroup {
	forgotten := &rsaGroupUnknownOrder{
		UnitGroupTrait: internal.UnitGroupTrait[*rsaGroupUnknownOrder, *rsaUnitUnknownOrder, *rsaUnitUnknownOrder, rsaUnitUnknownOrder]{
			BaseRing: g.BaseRing,
		},
	}
	forgotten.Group = forgotten
	return forgotten
}

func (g *rsaGroupKnownOrder) Arithmetic() *modular.OddPrimeFactors {
	return g.arith
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
	arith, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, errs.NewValue("failed to create OddPrimeFactors")
	}
	return &rsaGroupKnownOrder{
		UnitGroupTrait: internal.UnitGroupTrait[*rsaGroupKnownOrder, *rsaUnitKnownOrder, *rsaUnitKnownOrder, rsaUnitKnownOrder]{
			BaseRing: zMod,
		},
		p:     p,
		q:     q,
		arith: arith,
	}, nil
}

func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (RSAGroup, error) {
	out, err := NewUnitGroupOfUnknownOrder(m)
	if err != nil {
		return nil, err
	}
	return &rsaGroup{
		UnitGroupTrait: *out.(*uZMod),
	}, nil
}
