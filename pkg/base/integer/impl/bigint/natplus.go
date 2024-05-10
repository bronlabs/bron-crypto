package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
)

var _ integer.NatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)

type NatPlus struct {
	impl.PositiveNatMixin[*NPlus, *NatPlus, *BigInt]
}

func (*NatPlus) Structure() *NPlus {
	return &NPlus{}
}

func (n *NatPlus) Unwrap() *NatPlus {
	return n
}

func (n *NatPlus) unwrap() *BigInt {
	return n.V
}

func (n *NatPlus) new(x *BigInt) (*NatPlus, error) {
	arith := NewNPlusArithmetic()
	if arith.Cmp(x, Zero) == algebra.LessThan {
		return nil, errs.NewValue("input not in range")
	}
	mixin := impl.NewPositiveNatMixin[*NPlus, *NatPlus, *BigInt](arith, n.new, x)
	return &NatPlus{
		*mixin,
	}, nil

}

func (n *NatPlus) New(x *big.Int) (*NatPlus, error) {
	return n.new(B(x))
}

func (n *NatPlus) Clone() *NatPlus {
	mixin := n.PositiveNatMixin.Clone()
	return &NatPlus{
		PositiveNatMixin: mixin,
	}
}

func (n *NatPlus) Chain() algebra.Chain[*NPlus, *NatPlus] {
	return &NPlus{}
}

// func NewPositiveNat(v *big.Int) (*NatPlus, error) {
// 	if v == nil {
// 		return nil, errs.NewIsNil("v")
// 	}
// 	vv := B(v)
// 	arithmetic := NewNPlusArithmetic()
// 	if arithmetic.Cmp(vv, arithmetic.One()) == algebra.LessThan {
// 		return nil, errs.NewValue("v < 1")
// 	}
// 	res := &NatPlus{}
// 	return &NatPlus{
// 		impl.NewPositiveNatMixin[*NPlus, *NatPlus, *BigInt](arithmetic, n.new, x),
// 	}, nil
// }
