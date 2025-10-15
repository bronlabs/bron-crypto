package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
)

type RSAGroup UnitGroup[RSAUnit]

type RSAUnit Unit[RSAUnit]

type RSAGroupKnownOrder interface {
	RSAGroup
	KnowledgeOfOrder[*modular.OddPrimeFactors, RSAGroup, RSAUnit]
}

// // ====================

// func NewRSAGroup(p, q *num.NatPlus) (RSAGroupKnownOrder, error) {
// 	if p == nil || q == nil {
// 		return nil, errs.NewValue("p and q must not be nil")
// 	}
// 	if p.AnnouncedLen() != q.AnnouncedLen() {
// 		return nil, errs.NewValue("p and q must have the same length")
// 	}
// 	if !p.IsProbablyPrime() {
// 		return nil, errs.NewValue("p must be prime")
// 	}
// 	if !q.IsProbablyPrime() {
// 		return nil, errs.NewValue("q must be prime")
// 	}
// 	zMod, err := num.NewZMod(p.Mul(q))
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ZMod")
// 	}
// 	exp, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
// 	if ok == ct.False {
// 		return nil, errs.NewValue("failed to create OddPrimeFactors")
// 	}
// 	return &rsaGroupKnownOrder{
// 		UnitGroupKnownOrderTrait: UnitGroupKnownOrderTrait[*modular.OddPrimeFactors]{
// 			zMod:  zMod,
// 			arith: exp,
// 		},
// 	}, nil
// }

// func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (RSAGroup, error) {
// 	out, err := NewUnitGroupOfUnknownOrder(m)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &rsaGroup{
// 		UnitGroupTrait: *out.(*uZMod),
// 	}, nil
// }

// type rsaGroup struct {
// 	UnitGroupTrait
// }

// type rsaGroupKnownOrder struct {
// 	UnitGroupKnownOrderTrait[*modular.OddPrimeFactors]
// }

// func (rg *rsaGroupKnownOrder) Arithmetic() *modular.OddPrimeFactors {
// 	return rg.arith
// }

// func (rg *rsaGroupKnownOrder) ForgetOrder() RSAGroup {
// 	return &rsaGroup{
// 		UnitGroupTrait: UnitGroupTrait{
// 			zMod: rg.UnitGroupKnownOrderTrait.zMod,
// 		},
// 	}
// }

// func (rg *rsaGroupKnownOrder) FromUint(input *num.Uint) (Unit, error) {
// 	u, err := rg.UnitGroupKnownOrderTrait.FromUint(input)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// Fix the group pointer to point to the known order wrapper
// 	u.(*unitKnownOrder[*modular.OddPrimeFactors]).g = rg
// 	return u, nil
// }
