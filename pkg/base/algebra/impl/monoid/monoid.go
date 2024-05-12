package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Monoid[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] struct {
	groupoid.Groupoid[M, E]
	monoid[M, E]
}

type AdditiveMonoid[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] struct {
	additiveMonoid[M, E]
	Monoid[M, E]
}

func (m *AdditiveMonoid[M, E]) AdditiveIdentity() E {
	out, err := m.Identity(m.Addition().Name())
	if err != nil {
		panic(errs.WrapFailed(err, "additive monoid is malformed"))
	}
	return out
}

type MultiplicativeMonoid[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] struct {
	multiplicativeMonoid[M, E]
	Monoid[M, E]
}

func (m *MultiplicativeMonoid[M, E]) MultiplicativeIdentity() E {
	out, err := m.Identity(m.Multiplication().Name())
	if err != nil {
		panic(errs.WrapFailed(err, "multiplicative monoid is malformed"))
	}
	return out
}

type CyclicMonoid[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] struct {
	cyclicMonoid[M, E]
	Monoid[M, E]
}
