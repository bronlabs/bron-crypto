package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type MonoidElement[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] struct {
	algebra.MonoidElement[M, E]
}

func (e *MonoidElement[M, E]) IsIdentity(under algebra.BinaryOperator[E]) (bool, error) {
	if !e.Structure().IsDefinedUnder(under) {
		return false, errs.NewArgument("invalid operator")
	}
	identity, err := e.Structure().Identity(under)
	if err != nil {
		return false, errs.WrapFailed(err, "could not compute curve identity under given operator")
	}
	return identity.Equal(e.Unwrap()), nil
}

type AdditiveMonoidElement[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] struct {
	algebra.AdditiveMonoidElement[M, E]
}

func (e *AdditiveMonoidElement[M, E]) IsAdditiveIdentity() bool {
	return e.Equal(e.Structure().AdditiveIdentity())
}

type MultiplicativeMonoidElement[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] struct {
	algebra.MultiplicativeMonoidElement[M, E]
}

func (e *MultiplicativeMonoidElement[M, E]) IsMultiplicativeIdentity() bool {
	return e.Equal(e.Structure().MultiplicativeIdentity())
}
