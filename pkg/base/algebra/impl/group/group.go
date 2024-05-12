package group

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
)

type Group[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	group[G, E]
	groupoid.Groupoid[G, E]
	monoid.Monoid[G, E]
}

type AdditiveGroup[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] struct {
	additiveGroup[G, E]
	groupoid.AdditiveGroupoid[G, E]
	monoid.AdditiveMonoid[G, E]
}

func (*AdditiveGroup[G, E]) Sub(x algebra.AdditiveGroupElement[G, E], ys ...algebra.AdditiveGroupElement[G, E]) E {
	sum := x
	for _, y := range ys {
		sum = sum.Sub(y)
	}
	return sum.Unwrap()
}

type MultiplicativeGroup[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] struct {
	multiplicativeGroup[G, E]
	groupoid.MultiplicativeGroupoid[G, E]
	monoid.MultiplicativeMonoid[G, E]
}

func (*MultiplicativeGroup[G, E]) Div(x algebra.MultiplicativeGroupElement[G, E], ys ...algebra.MultiplicativeGroupElement[G, E]) (E, error) {
	var err error
	res := x
	for _, y := range ys {
		res, err = x.Div(y)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not divide x by y")
		}
	}
	return res.Unwrap(), nil
}

type CyclicGroup[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] struct {
	// cyclicGroup[G, E]
	cyclicGroup2[G, E]
	// groupoid.CyclicGroupoid[G, E]
	monoid.CyclicMonoid[G, E]
}

func (g *CyclicGroup[G, E]) DLog(base, x algebra.CyclicGroupElement[G, E], under algebra.Operator) (*saferith.Nat, error) {
	if _, defined := g.Operator(under); !defined {
		return nil, errs.NewType("invalid operator")
	}
	order := g.Order().Nat()
	exponent := new(saferith.Nat).SetUint64(1)
	for exponent.Eq(order) != 1 {
		bexp, err := base.Apply(under, base, exponent)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not raise b to current exponent")
		}
		if x.Equal(bexp) {
			return exponent, nil
		}
		exponent = saferith_utils.NatInc(exponent)
	}
	bexp, err := base.Apply(under, base, exponent)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not raise b to current exponent")
	}
	if !x.Equal(bexp) {
		return nil, errs.WrapFailed(err, "could not find dlog")
	}
	return exponent, nil
}
