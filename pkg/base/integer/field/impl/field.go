package impl

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	uimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/uints/impl"
)

type Zp_[S integer.Zp[S, E], E integer.IntP[S, E]] struct {
	groupoid.Groupoid[S, E]
	uimpl.Zn_[S, E]
	group.MultiplicativeGroup[S, E]
	H HolesZp[S, E]
}

func (z *Zp_[S, E]) RandomPrime(prng io.Reader) E {
	panic("implement me")
}

type wrapped[S integer.Zp[S, E], E integer.IntP[S, E]] struct {
	group.MultiplicativeGroupElement[S, E]
}

type IntP_[S integer.Zp[S, E], E integer.IntP[S, E]] struct {
	wrapped[S, E]
	uimpl.Uint_[S, E]
	H HolesIntP[S, E]
}

func (i *IntP_[S, E]) MultiplicativeInverse() (E, error) {
	arith := i.H.ModularArithmetic()
	out, err := arith.Inverse(i.H.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "does not have multiplicative inverse")
	}
	return out, nil
}
