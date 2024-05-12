package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type NPlus[S algebra.Structure, E algebra.Element, N any] struct {
}

type NatPlus[S algebra.Structure, E algebra.Element, N any] struct {
	arithmetic integer.Arithmetic[N]
	impl       func(E) N
	toE        func(N) E
	V          N
}

func (n *NatPlus[S, E, N]) Add(x algebra.AdditiveGroupoidElement[S, E]) E {
	res, err := n.arithmetic.Add(n.V, n.impl(x.Unwrap()))
	if err != nil {
		panic(err)
	}
	return n.toE(res)
}

func (n *NatPlus[S, E, N]) Cmp(rhs algebra.OrderTheoreticLatticeElement[S, E]) algebra.Ordering {
	return n.arithmetic.Cmp(n.V, n.impl(rhs.Unwrap()))
}
