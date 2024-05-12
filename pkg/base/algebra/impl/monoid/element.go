package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type MonoidElement[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] struct {
	monoidElement[M, E]
	groupoid.GroupoidElement[M, E]
}

func (e *MonoidElement[M, E]) IsIdentity(under algebra.Operator) (bool, error) {
	if _, defined := e.Structure().Operator(under); !defined {
		return false, errs.NewType("invalid operator")
	}
	identity, err := e.Structure().Identity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not compute curve identity under given operator")
	}
	return identity.Equal(e.Unwrap()), nil
}

type AdditiveMonoidElement[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] struct {
	additiveMonoidElement[M, E]
	MonoidElement[M, E]
	groupoid.AdditiveGroupoidElement[M, E]
}

func (e *AdditiveMonoidElement[M, E]) IsAdditiveIdentity() bool {
	return e.Equal(e.Structure().AdditiveIdentity())
}

type MultiplicativeMonoidElement[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] struct {
	multiplicativeMonoidElement[M, E]
	MonoidElement[M, E]
	groupoid.MultiplicativeGroupoidElement[M, E]
}

func (e *MultiplicativeMonoidElement[M, E]) IsMultiplicativeIdentity() bool {
	return e.Equal(e.Structure().MultiplicativeIdentity())
}

type CyclicMonoidElement[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] struct {
	cyclicMonoidElement[M, E]
	MonoidElement[M, E]
	groupoid.CyclicGroupoidElement[M, E]
}
