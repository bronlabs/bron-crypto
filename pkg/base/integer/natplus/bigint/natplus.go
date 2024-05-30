package bigint

import (
	"encoding/json"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/impl"
	"github.com/cronokirby/saferith"
)

var Name = fmt.Sprintf("%s_N+", bg.Name)

var _ integer.NatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)
var _ integer.NaturalSemiRingElement[*NPlus, *NatPlus] = (*NatPlus)(nil)

var _ impl.HolesNatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)
var _ aimpl.ImplAdapter[*NatPlus, *bg.BigInt] = (*NatPlus)(nil)
var _ integer.Number[*NatPlus] = (*NatPlus)(nil)

type NatPlus struct {
	impl.NatPlus[*NPlus, *NatPlus]
	V *bg.BigInt
}

func NewNatPlus(v uint64) *NatPlus {
	self := &NatPlus{
		V: new(bg.BigInt).SetUint64(v),
	}
	self.NatPlus = impl.NewNatPlus(self)
	return self
}

func (n *NatPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return bg.NewUnsignedPositiveArithmetic[*NatPlus](-1, false)
}

func (*NatPlus) Structure() *NPlus {
	return &NPlus{}
}

func (n *NatPlus) Unwrap() *NatPlus {
	return n
}

func (n *NatPlus) Impl() *bg.BigInt {
	return n.V
}

func (n *NatPlus) New(x *bg.BigInt) *NatPlus {
	out := &NatPlus{
		V: x,
	}
	out.NatPlus = impl.NewNatPlus(out)
	return out
}

func (n *NatPlus) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *NatPlus) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *NatPlus) Clone() *NatPlus {
	return n.New(n.V)
}

func (n *NatPlus) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *NatPlus) SetNat(v *saferith.Nat) *NatPlus {
	res := n.New(new(bg.BigInt).SetNat(v))
	n.V = res.V
	return n
}

func (n *NatPlus) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *bg.BigInt
	}
	return json.Marshal(&temp{
		Name:   Name,
		Number: n.V,
	})
}

func (n *NatPlus) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Number *bg.BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != Name {
		return errs.NewType("name (%s) must be (%s)", temp.Name, Name)
	}
	if temp.Number.Cmp(bg.One) == algebra.LessThan {
		return errs.NewValue("number is not a natplus")
	}
	n.V = temp.Number
	n.NatPlus = impl.NewNatPlus(n)
	return nil
}
