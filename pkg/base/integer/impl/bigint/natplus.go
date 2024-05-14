package bigint

import (
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/cronokirby/saferith"
)

var _ integer.NatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)
var _ aimpl.ImplAdapter[*NatPlus, *BigInt] = (*NatPlus)(nil)
var _ integer.Number[*NatPlus] = (*NatPlus)(nil)

type NatPlus struct {
	impl.NatPlusMixin[*NPlus, *NatPlus]
	V *BigInt
}

func New(v uint64) *NatPlus {
	return &NatPlus{
		V: new(BigInt).SetUint64(v),
	}
}

func (n *NatPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return NewNPlusArithmetic[*NatPlus](-1, true)
}

func (n *NatPlus) Mul(x algebra.MultiplicativeGroupoidElement[*NPlus, *NatPlus]) *NatPlus {
	out, err := n.Arithmetic().Mul(n.Unwrap(), x.Unwrap())
	if err != nil {
		panic(err)
	}
	return out
}

func (*NatPlus) Structure() *NPlus {
	return &NPlus{}
}

func (n *NatPlus) Unwrap() *NatPlus {
	return n
}

func (n *NatPlus) Impl() *BigInt {
	return n.V
}

func (n *NatPlus) Wrap(x *BigInt) *NatPlus {
	out := new(NatPlus)
	out.V = x
	return out
}

func (n *NatPlus) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *NatPlus) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *NatPlus) Clone() *NatPlus {
	return &NatPlus{
		NatPlusMixin: impl.NatPlusMixin[*NPlus, *NatPlus]{},
		V:            n.V.Clone(),
	}
}

func (n *NatPlus) Nat() *saferith.Nat {
	return n.V.Nat()
}

func (n *NatPlus) SetNat(v *saferith.Nat) *NatPlus {
	out := &NatPlus{}
	out.V = new(BigInt).SetNat(v)
	return out
}

func (n *NatPlus) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Type   integer.ArithmeticType
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   n.Arithmetic().Name(),
		Type:   integer.ForNPlus,
		Number: n.V,
	})
}

func (n *NatPlus) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Type   integer.ArithmeticType
		Number *BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if string(temp.Type) != string(integer.ForNPlus) {
		return errs.NewType("type (%s) must be (%s)", temp.Type, integer.ForNPlus)
	}
	n.V = temp.Number
	return nil
}
