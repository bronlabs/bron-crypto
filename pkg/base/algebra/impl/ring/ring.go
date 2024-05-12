package rg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
)

type T[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	algebra.Rg[R, E]
}

type Rg[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	groupoid.Groupoid[R, E]
	groupoid.AdditiveGroupoid[R, E]
	groupoid.MultiplicativeGroupoid[R, E]
	T[R, E]
}

func (r Rg[R, E]) test() {
	r.Add
	r.Order
	r.Random
}
