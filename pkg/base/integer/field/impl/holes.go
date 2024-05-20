package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	uimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/uints/impl"
)

type HolesZp[S integer.Zp[S, E], E integer.IntP[S, E]] interface {
	groupoid.HolesGroupoid[S, E]
	group.HolesMultiplicativeGroup[S, E]
	uimpl.HolesZn[S, E]
}

type HolesIntP[S integer.Zp[S, E], E integer.IntP[S, E]] interface {
	uimpl.HolesUint[S, E]
	group.HolesMultiplicativeGroupElement[S, E]
}

func NewZp_[S integer.Zp[S, E], E integer.IntP[S, E]](arithmetic integer.Arithmetic[E], H HolesZp[S, E]) Zp_[S, E] {
	return Zp_[S, E]{
		Groupoid:            groupoid.NewGroupoid(H),
		Zn_:                 uimpl.NewZn_(arithmetic, H),
		MultiplicativeGroup: group.NewMultiplicativeGroup(H),
		H:                   H,
	}
}

func NewIntP_[S integer.Zp[S, E], E integer.IntP[S, E]](H HolesIntP[S, E]) IntP_[S, E] {
	return IntP_[S, E]{
		Uint_: uimpl.NewUint_(H),
		wrapped: wrapped[S, E]{
			MultiplicativeGroupElement: group.NewMultiplicativeGroupElement(H),
		},
		H: H,
	}
}
