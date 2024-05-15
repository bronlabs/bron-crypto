package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Monoid[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] struct {
	groupoid.Groupoid[M, E]
	H HolesMonoid[M, E]
}

type AdditiveMonoid[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] struct {
	Monoid[M, E]
	groupoid.AdditiveGroupoid[M, E]
	H HolesAdditiveMonoid[M, E]
}

func (m *AdditiveMonoid[M, E]) AdditiveIdentity() E {
	out, err := m.H.Identity(m.H.Addition().Name())
	if err != nil {
		panic(errs.WrapFailed(err, "additive monoid is malformed"))
	}
	return out.Unwrap()
}

type MultiplicativeMonoid[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] struct {
	Monoid[M, E]
	groupoid.MultiplicativeGroupoid[M, E]
	H HolesMultiplicativeMonoid[M, E]
}

func (m *MultiplicativeMonoid[M, E]) MultiplicativeIdentity() E {
	out, err := m.H.Identity(m.H.Multiplication().Name())
	if err != nil {
		panic(errs.WrapFailed(err, "multiplicative monoid is malformed"))
	}
	return out.Unwrap()
}

type CyclicMonoid[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] struct {
	Monoid[M, E]
	groupoid.CyclicGroupoid[M, E]
	H HolesCyclicMonoid[M, E]
}
