package algebrautils

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

// RandomNonIdentity samples a random element from the given finite monoid that is not the identity element.
func RandomNonIdentity[M interface {
	algebra.FiniteStructure[E]
	algebra.Monoid[E]
}, E algebra.MonoidElement[E]](m M, prng io.Reader) (E, error) {
	validationErrors := []error{}
	if utils.IsNil(m) {
		validationErrors = append(validationErrors, ErrArgumentIsNil.WithMessage("monoid"))
	}
	if prng == nil {
		validationErrors = append(validationErrors, ErrArgumentIsNil.WithMessage("prng"))
	}
	if len(validationErrors) > 0 {
		return *new(E), errs2.Join(validationErrors...)
	}
	var err error
	out := m.OpIdentity()
	for out.IsOpIdentity() {
		out, err = m.Random(prng)
		if err != nil {
			return *new(E), errs2.Wrap(err)
		}
	}
	return out, nil
}

// Fold applies the binary operation of the given operand type to all provided elements, returning the final result.
func Fold[S algebra.Operand[S]](first S, rest ...S) S {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc S, e S) S {
		return acc.Op(e)
	})
}

// Sum applies the addition operation of the given summand type to all provided elements, returning the final result.
func Sum[S algebra.Summand[S]](first S, rest ...S) S {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc S, e S) S {
		return acc.Add(e)
	})
}

// Prod applies the multiplication operation of the given multiplicand type to all provided elements, returning the final result.
func Prod[M algebra.Multiplicand[M]](first M, rest ...M) M {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc M, e M) M {
		return acc.Mul(e)
	})
}

// ScalarMul computes the scalar multiplication of the given base element by the given exponent using a fixed-window method.
func ScalarMul[E algebra.MonoidElement[E]](base E, exponent *num.Nat) E {
	monoid := algebra.StructureMustBeAs[algebra.Monoid[E]](base.Structure())

	precomputed := make([]E, 16)
	precomputed[0] = monoid.OpIdentity()
	precomputed[1] = base
	for i := 2; i < 16; i += 2 {
		precomputed[i] = precomputed[i/2].Op(precomputed[i/2])
		precomputed[i+1] = precomputed[i].Op(base)
	}

	res := monoid.OpIdentity()
	exponentBigEndianBytes := exponent.Bytes()
	for _, si := range exponentBigEndianBytes {
		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		w := (si >> 4) & 0b1111
		res = res.Op(precomputed[w])

		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		w = si & 0b1111
		res = res.Op(precomputed[w])
	}

	return res
}

var ErrArgumentIsNil = errs2.New("argument is nil")
