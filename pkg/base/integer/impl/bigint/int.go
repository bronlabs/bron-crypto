package bigint

import (
	"encoding/json"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
	"github.com/cronokirby/saferith"
)

var zName = fmt.Sprintf("%s_Z", Name)

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
	return n.New(new(BigInt).SetNat(v))
}

func (n *Int) Arithmetic() integer.Arithmetic[*Int] {
	return NewSignedArithmetic[*Int](-1, false)
}

func (n *Int) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   Name,
		Number: n.V,
	})
}

func (n *Int) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Number *BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != Name {
		return errs.NewType("name (%s) must be (%s)", temp.Name, nName)
	}
	n.V = temp.Number
	n.Int_ = mixins.NewInt_(n)
	return nil
}

type Z struct {
	mixins.Z_[*Z, *Int]
}

func (z *Z) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (*Z) Name() string {
	return zName
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
