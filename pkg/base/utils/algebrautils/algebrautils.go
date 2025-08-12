package algebrautils

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

func RandomNonIdentity[M interface {
	algebra.FiniteStructure[E]
	algebra.Monoid[E]
}, E algebra.MonoidElement[E]](m M, prng io.Reader) (E, error) {
	if utils.IsNil(m) {
		return *new(E), errs.NewIsNil("nil monoid")
	}
	if prng == nil {
		return *new(E), errs.NewIsNil("nil prng")
	}
	var err error
	out := m.OpIdentity()
	for out.IsOpIdentity() {
		out, err = m.Random(prng)
		if err != nil {
			return *new(E), errs.WrapRandomSample(err, "failed to sample random element")
		}
	}
	return out, nil
}

func Fold[S algebra.Operand[S]](first S, rest ...S) S {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc S, e S) S {
		return acc.Op(e)
	})
}

func Sum[S algebra.Summand[S]](first S, rest ...S) S {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc S, e S) S {
		return acc.Add(e)
	})
}

func Prod[M algebra.Multiplicand[M]](first M, rest ...M) M {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc M, e M) M {
		return acc.Mul(e)
	})
}
