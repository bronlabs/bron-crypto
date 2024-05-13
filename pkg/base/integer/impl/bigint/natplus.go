package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/cronokirby/saferith"
)

var _ integer.NatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)

type NatPlus struct {
	impl.NatPlusMixin[*NPlus, *NatPlus]
	// order.ChainElement[*NPlus, *NatPlus]
}

func (n *NatPlus) Apply(with algebra.Operator, x algebra.GroupoidElement[*NPlus, *NatPlus], count *saferith.Nat) (*NatPlus, error) {
	return n.GroupoidElement.Apply(with, x, count)
}

// func (n *NatPlus) Join(rhs algebra.OrderTheoreticLatticeElement[*NPlus, *NatPlus]) *NatPlus {
// 	return n.ChainElement.Join(rhs)
// }

func (n *NatPlus) CanGenerateAllElements(with algebra.Operator) bool {
	_, defined := n.Structure().GetOperator(with)
	return n.IsOne() && defined && n.Structure().Addition().Name() == with
}

func (*NatPlus) Structure() *NPlus {
	return &NPlus{}
}

func (n *NatPlus) Unwrap() *NatPlus {
	return n
}

func (n *NatPlus) Clone() *NatPlus {
	return n.Arithmetic().Clone(n)
}

func (n *NatPlus) AnnouncedLen() int {
	panic("implement me")
}
