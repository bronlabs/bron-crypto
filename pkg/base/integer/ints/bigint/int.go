package bigint

import (
	"encoding/json"
	"fmt"
	"math/big"

	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/ints/impl"
	"github.com/cronokirby/saferith"
)

var zName = fmt.Sprintf("%s_Z", bg.Name)

var _ integer.Int[*Z, *Int] = (*Int)(nil)

var _ impl.HolesInt[*Z, *Int] = (*Int)(nil)
var _ aimpl.ImplAdapter[*Int, *bg.BigInt] = (*Int)(nil)
var _ integer.Number[*Int] = (*Int)(nil)

type Int struct {
	impl.Int_[*Z, *Int]
	V *bg.BigInt
}

func (n *Int) New(x *bg.BigInt) *Int {
	out := &Int{
		V: x,
	}
	out.Int_ = impl.NewInt_(out)
	return out
}

func (*Int) Structure() *Z {
	return &Z{}
}

func (n *Int) Unwrap() *Int {
	return n
}

func (n *Int) Impl() *bg.BigInt {
	return n.V
}

func (n *Int) GCD(x *Int) (*Int, error) {
	return n.New(n.V.GCD(x.V)), nil
}

func (n *Int) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *Int) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *Int) Clone() *Int {
	return n.New(n.V)
}

func (n *Int) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *Int) SetNat(v *saferith.Nat) *Int {
	out := n.New(new(bg.BigInt).SetNat(v))
	n.V = out.V
	return n
}

func (n *Int) Int() *saferith.Int {
	return new(saferith.Int).SetBig(n.V.V, -1)
}

func (n *Int) SetInt(v *saferith.Int) *Int {
	out := n.New(new(bg.BigInt).New(v.Big()))
	n.V = out.V
	return n
}

func (n *Int) Big() *big.Int {
	return n.V.V
}

func (n *Int) SetBig(v *big.Int) *Int {
	out := n.New(new(bg.BigInt).New(v))
	n.V = out.V
	return n
}

func (n *Int) Arithmetic() integer.Arithmetic[*Int] {
	return bg.NewSignedArithmetic[*Int](-1, false)
}

func (n *Int) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *bg.BigInt
	}
	return json.Marshal(&temp{
		Name:   zName,
		Number: n.V,
	})
}

func (n *Int) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Number *bg.BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != zName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, zName)
	}
	n.V = temp.Number
	n.Int_ = impl.NewInt_(n)
	return nil
}

func NewInt(v int64) integer.Int[*Z, *Int] {
	return new(Int).New(bg.New(new(big.Int).SetInt64(v)))
}
