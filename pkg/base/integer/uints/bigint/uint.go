package bigint

import (
	"encoding/json"
	"fmt"

	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/uints/impl"
	"github.com/cronokirby/saferith"
)

var znName = fmt.Sprintf("%s_Zn", bg.Name)

var _ integer.Uint[*Zn, *Uint] = (*Uint)(nil)

var _ impl.HolesUint[*Zn, *Uint] = (*Uint)(nil)
var _ aimpl.ImplAdapter[*Uint, *bg.BigInt] = (*Uint)(nil)
var _ integer.Number[*Uint] = (*Uint)(nil)

type Uint struct {
	impl.Uint_[*Zn, *Uint]
	V *bg.BigInt
}

func (n *Uint) New(x *bg.BigInt) *Uint {
	out := &Uint{
		V: x,
	}
	out.Uint_ = impl.NewUint_(out)
	return out
}

func (*Uint) Structure() *Zn {
	return &Zn{}
}

func (n *Uint) Unwrap() *Uint {
	return n
}

func (n *Uint) Impl() *bg.BigInt {
	return n.V
}

func (n *Uint) GCD(x *Uint) (*Uint, error) {
	return n.New(n.V.GCD(x.V)), nil
}

func (n *Uint) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *Uint) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *Uint) Clone() *Uint {
	return n.New(n.V)
}

func (n *Uint) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *Uint) SetNat(v *saferith.Nat) *Uint {
	return n.New(new(bg.BigInt).SetNat(v))
}

func (n *Uint) Arithmetic() integer.Arithmetic[*Uint] {
	return n.Structure().ModularArithmetic()
}

func (n *Uint) ModularArithmetic() integer.ModularArithmetic[*Uint] {
	return n.Structure().ModularArithmetic()
}

func (n *Uint) Bytes() []byte {
	return n.V.V.Bytes()
}

func (n *Uint) SetBytes(input []byte) (*Uint, error) {
	return n.New(n.V.SetBytes(input)), nil
}

func (n *Uint) SetBytesWide(input []byte) (*Uint, error) {
	return n.SetBytes(input)
}

func (n *Uint) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *bg.BigInt
	}
	return json.Marshal(&temp{
		Name:   znName,
		Number: n.V,
	})
}

func (n *Uint) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Number *bg.BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != znName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, znName)
	}
	n.V = temp.Number
	n.Uint_ = impl.NewUint_(n)
	return nil
}
