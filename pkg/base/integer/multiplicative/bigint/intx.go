package bigint

import (
	"encoding/json"
	"fmt"

	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/multiplicative"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/multiplicative/impl"
	"github.com/cronokirby/saferith"
)

var Name = fmt.Sprintf("%s_Zp", bg.Name)

var _ multiplicative.IntX[*ZnX, *IntX] = (*IntX)(nil)

var _ impl.HolesIntX[*ZnX, *IntX] = (*IntX)(nil)
var _ aimpl.ImplAdapter[*IntX, *bg.BigInt] = (*IntX)(nil)
var _ integer.Number[*IntX] = (*IntX)(nil)

type IntX struct {
	impl.IntX_[*ZnX, *IntX]
	V *bg.BigInt
}

func (n *IntX) New(x *bg.BigInt) *IntX {
	out := &IntX{
		V: x,
	}
	out.IntP_ = impl.NewIntP_(out)
	return out
}

func (*IntX) Structure() *ZnX {
	return &ZnX{}
}

func (n *IntX) Unwrap() *IntX {
	return n
}

func (n *IntX) Impl() *bg.BigInt {
	return n.V
}

func (n *IntX) GCD(x *IntX) (*IntX, error) {
	return n.New(n.V.GCD(x.V)), nil
}

func (n *IntX) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *IntX) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *IntX) Clone() *IntX {
	return n.New(n.V)
}

func (n *IntX) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *IntX) SetNat(v *saferith.Nat) *IntX {
	return n.New(new(bg.BigInt).SetNat(v))
}

func (n *IntX) Arithmetic() integer.Arithmetic[*IntX] {
	return n.Structure().ModularArithmetic()
}

func (n *IntX) ModularArithmetic() integer.ModularArithmetic[*IntX] {
	return n.Structure().ModularArithmetic()
}

func (n *IntX) Bytes() []byte {
	return n.V.V.Bytes()
}

func (n *IntX) SetBytes(input []byte) (*IntX, error) {
	return n.New(n.V.SetBytes(input)), nil
}

func (n *IntX) SetBytesWide(input []byte) (*IntX, error) {
	return n.SetBytes(input)
}

func (n *IntX) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *bg.BigInt
	}
	return json.Marshal(&temp{
		Name:   Name,
		Number: n.V,
	})
}

func (n *IntX) UnmarshalJSON(data []byte) error {
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
