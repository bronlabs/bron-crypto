package nt

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// *** Prime Factors ***

func NewIntegerPrimeFactorisation[E algebra.UniqueFactorizationMonoidElement[E], P algebra.NatLike[P]](n E, factorsToExponents ds.Map[P, P]) (*PrimeFactorisation[E, P], error) {
	if utils.IsNil(n) {
		return nil, errs.NewIsNil("n")
	}
	if n.IsOpIdentity() {
		return nil, errs.NewValue("n must not be identity")
	}
	if factorsToExponents == nil {
		return nil, errs.NewIsNil("argument")
	}
	if sliceutils.Any(factorsToExponents.Values(), func(exp P) bool { return exp.IsOpIdentity() }) {
		return nil, errs.NewValue("exponents must not be identity")
	}
	return &PrimeFactorisation[E, P]{n: n, ps: factorsToExponents}, nil
}

type PrimeFactorisation[E algebra.UniqueFactorizationMonoidElement[E], P algebra.MonoidElement[P]] struct {
	n  E
	ps ds.Map[P, P]
}

func (pf *PrimeFactorisation[E, ENP]) N() E {
	return pf.n
}

func (pf *PrimeFactorisation[E, ENP]) GetExponent(factor ENP) (ENP, bool) {
	if pf == nil {
		panic("receiver is nil")
	}
	return pf.ps.Get(factor)
}

func (pf *PrimeFactorisation[E, ENP]) IsPrimeProduct() bool {
	return sliceutils.All(pf.ps.Values(), func(exp ENP) bool {
		return exp.IsOpIdentity()
	})
}
