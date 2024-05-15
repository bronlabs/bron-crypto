package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type MonoidElement[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] struct {
	groupoid.GroupoidElement[M, E]
	H HolesMonoidElement[M, E]
}

func (e *MonoidElement[M, E]) IsIdentity(under algebra.Operator) (bool, error) {
	if _, defined := e.H.Structure().GetOperator(under); !defined {
		return false, errs.NewType("invalid operator")
	}
	identity, err := e.H.Structure().Identity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not compute curve identity under given operator")
	}
	return identity.Equal(e.H.Unwrap()), nil
}

type AdditiveMonoidElement[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] struct {
	MonoidElement[M, E]
	groupoid.AdditiveGroupoidElement[M, E]
	H HolesAdditiveMonoidElement[M, E]
}

func (e *AdditiveMonoidElement[M, E]) IsAdditiveIdentity() bool {
	return e.H.Equal(e.H.Structure().AdditiveIdentity())
}

type MultiplicativeMonoidElement[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] struct {
	MonoidElement[M, E]
	groupoid.MultiplicativeGroupoidElement[M, E]
	H HolesMultiplicativeMonoidElement[M, E]
}

func (e *MultiplicativeMonoidElement[M, E]) IsMultiplicativeIdentity() bool {
	return e.H.Equal(e.H.Structure().MultiplicativeIdentity())
}

type CyclicMonoidElement[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] struct {
	MonoidElement[M, E]
	groupoid.CyclicGroupoidElement[M, E]
	H HolesCyclicMonoidElement[M, E]
}
