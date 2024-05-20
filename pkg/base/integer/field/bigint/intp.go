package bigint

import (
	"encoding/json"
	"fmt"

	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/field/impl"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/cronokirby/saferith"
)

var Name = fmt.Sprintf("%s_Zp", bg.Name)

var _ integer.IntP[*Zp, *IntP] = (*IntP)(nil)

var _ impl.HolesIntP[*Zp, *IntP] = (*IntP)(nil)
var _ aimpl.ImplAdapter[*IntP, *bg.BigInt] = (*IntP)(nil)
var _ integer.Number[*IntP] = (*IntP)(nil)

type IntP struct {
	impl.IntP_[*Zp, *IntP]
	V *bg.BigInt
}

func (n *IntP) New(x *bg.BigInt) *IntP {
	out := &IntP{
		V: x,
	}
	out.IntP_ = impl.NewIntP_(out)
	return out
}

func (*IntP) Structure() *Zp {
	return &Zp{}
}

func (n *IntP) Unwrap() *IntP {
	return n
}

func (n *IntP) Impl() *bg.BigInt {
	return n.V
}

func (n *IntP) GCD(x *IntP) (*IntP, error) {
	return n.New(n.V.GCD(x.V)), nil
}

func (n *IntP) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *IntP) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *IntP) Clone() *IntP {
	return n.New(n.V)
}

func (n *IntP) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *IntP) SetNat(v *saferith.Nat) *IntP {
	return n.New(new(bg.BigInt).SetNat(v))
}

func (n *IntP) Arithmetic() integer.Arithmetic[*IntP] {
	return n.Structure().ModularArithmetic()
}

func (n *IntP) ModularArithmetic() integer.ModularArithmetic[*IntP] {
	return n.Structure().ModularArithmetic()
}

func (n *IntP) Bytes() []byte {
	return n.V.V.Bytes()
}

func (n *IntP) SetBytes(input []byte) (*IntP, error) {
	return n.New(n.V.SetBytes(input)), nil
}

func (n *IntP) SetBytesWide(input []byte) (*IntP, error) {
	return n.SetBytes(input)
}

func (n *IntP) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *bg.BigInt
	}
	return json.Marshal(&temp{
		Name:   Name,
		Number: n.V,
	})
}

func (n *IntP) UnmarshalJSON(data []byte) error {
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
	n.V = temp.Number
	n.IntP_ = impl.NewIntP_(n)
	return nil
}
