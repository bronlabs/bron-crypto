package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type MonoidElement[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] struct {
	groupoid.GroupoidElement[M, E]
}

func (*MonoidElement[M, E]) Structure() algebra.Monoid[M, E] {
	panic("in mixin")
}
func (*MonoidElement[M, E]) Equal(x E) bool {
	panic("in mixin")
}

func (e *MonoidElement[M, E]) IsIdentity(under algebra.Operator) (bool, error) {
	if _, defined := e.Structure().GetOperator(under); !defined {
		return false, errs.NewType("invalid operator")
	}
	identity, err := e.Structure().Identity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not compute curve identity under given operator")
	}
	return identity.Equal(e.Unwrap()), nil
}

type AdditiveMonoidElement[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] struct {
	MonoidElement[M, E]
	groupoid.AdditiveGroupoidElement[M, E]
}

func (*AdditiveMonoidElement[M, E]) Structure() algebra.AdditiveMonoid[M, E] {
	panic("in mixin")
}

func (e *AdditiveMonoidElement[M, E]) IsAdditiveIdentity() bool {
	return e.Equal(e.Structure().AdditiveIdentity())
}

type MultiplicativeMonoidElement[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] struct {
	MonoidElement[M, E]
	groupoid.MultiplicativeGroupoidElement[M, E]
}

func (*MultiplicativeMonoidElement[M, E]) Structure() algebra.MultiplicativeMonoid[M, E] {
	panic("in mixin")
}

func (e *MultiplicativeMonoidElement[M, E]) IsMultiplicativeIdentity() bool {
	return e.Equal(e.Structure().MultiplicativeIdentity())
}

type CyclicMonoidElement[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] struct {
	MonoidElement[M, E]
	groupoid.CyclicGroupoidElement[M, E]
}
