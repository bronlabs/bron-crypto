package bigint

import (
	"encoding/json"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/nat/impl"
	"github.com/cronokirby/saferith"
)

var natName = fmt.Sprintf("%s_N", bg.Name)

var _ integer.Nat[*N, *Nat] = (*Nat)(nil)
var _ integer.NaturalRigElement[*N, *Nat] = (*Nat)(nil)

var _ impl.HolesNat[*N, *Nat] = (*Nat)(nil)
var _ aimpl.ImplAdapter[*Nat, *bg.BigInt] = (*Nat)(nil)
var _ integer.Number[*Nat] = (*Nat)(nil)

type Nat struct {
	impl.Nat_[*N, *Nat]
	V *bg.BigInt
}

func NewNat(v uint64) *Nat {
	self := &Nat{
		V: new(bg.BigInt).SetUint64(v),
	}
	self.Nat_ = impl.NewNat_(self)
	return self
}

func (n *Nat) Arithmetic() integer.Arithmetic[*Nat] {
	return bg.NewUnsignedArithmetic[*Nat](-1, false)
}

func (n *Nat) GCD(x *Nat) (*Nat, error) {
	return n.New(n.V.GCD(x.V)), nil
}

func (*Nat) Structure() *N {
	return &N{}
}

func (n *Nat) Unwrap() *Nat {
	return n
}

func (n *Nat) Impl() *bg.BigInt {
	return n.V
}

func (n *Nat) New(x *bg.BigInt) *Nat {
	out := &Nat{
		V: x,
	}
	out.Nat_ = impl.NewNat_(out)
	return out
}

func (n *Nat) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *Nat) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *Nat) Clone() *Nat {
	return n.New(n.V)
}

func (n *Nat) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *Nat) SetNat(v *saferith.Nat) *Nat {
	res := n.New(new(bg.BigInt).SetNat(v))
	n.V = res.V
	return n
}

func (n *Nat) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *bg.BigInt
	}
	return json.Marshal(&temp{
		Name:   natName,
		Number: n.V,
	})
}

func (n *Nat) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Number *bg.BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != natName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, natName)
	}
	if temp.Number.Cmp(bg.Zero) == algebra.LessThan {
		return errs.NewValue("number is not a nat")
	}
	n.V = temp.Number
	n.Nat_ = impl.NewNat_(n)
	return nil
}
