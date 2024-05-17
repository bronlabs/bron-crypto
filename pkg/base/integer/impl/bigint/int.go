package bigint

import (
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
	"github.com/cronokirby/saferith"
)

type Int struct {
	mixins.Int_[*Z, *Int]
	V *BigInt
}

func (n *Int) New(x *BigInt) *Int {
	out := &Int{
		V: x,
	}
	out.Int_ = mixins.NewInt_(out)
	return out
}

func (*Int) Structure() *Z {
	return &Z{}
}

func (n *Int) Unwrap() *Int {
	return n
}

func (n *Int) Impl() *BigInt {
	return n.V
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
	return n.New(new(BigInt).SetNat(v))
}

func (n *Int) Arithmetic() integer.Arithmetic[*Int] {
	return NewSignedArithmetic[*Int](-1, false)
}

func (n *Int) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Type   integer.ArithmeticType
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   n.Arithmetic().Name(),
		Type:   integer.ForZ,
		Number: n.V,
	})
}

func (n *Int) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Type   integer.ArithmeticType
		Number *BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if string(temp.Type) != string(integer.ForZ) {
		return errs.NewType("type (%s) must be (%s)", temp.Type, integer.ForZ)
	}
	n.V = temp.Number
	n.Int_ = mixins.NewInt_(n)
	return nil
}

type Z struct {
	mixins.Z_[*Z, *Int]
}

func (z *Z) Element() *Int {
	return z.One()
}

func (z *Z) New(v uint64) *Int {
	return nil
}

func (z *Z) Unwrap() *Z {
	return z
}
