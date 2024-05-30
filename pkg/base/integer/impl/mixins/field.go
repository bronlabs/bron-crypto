package mixins

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type Zp[S integer.Zp[S, E], E integer.IntP[S, E]] struct {
	groupoid.Groupoid[S, E]
	Zn[S, E]
	group.MultiplicativeGroup[S, E]
	H HolesZp[S, E]
}

func (z *Zp[S, E]) RandomPrime(prng io.Reader) E {
	panic("implement me")
}

type wrapped[S integer.Zp[S, E], E integer.IntP[S, E]] struct {
	group.MultiplicativeGroupElement[S, E]
}

type IntP[S integer.Zp[S, E], E integer.IntP[S, E]] struct {
	wrapped[S, E]
	Uint[S, E]
	H HolesIntP[S, E]
}

func (i *IntP[S, E]) MultiplicativeInverse() (E, error) {
	arith := i.H.ModularArithmetic()
	out, err := arith.Inverse(i.H.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "does not have multiplicative inverse")
	}
	return out, nil
}
