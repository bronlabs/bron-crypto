package bigint

import (
	"encoding/json"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
	"github.com/cronokirby/saferith"
)

var nplusName = fmt.Sprintf("%s_N+", Name)

var _ mixins.HolesNatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)
var _ integer.NatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)
var _ aimpl.ImplAdapter[*NatPlus, *BigInt] = (*NatPlus)(nil)

type NatPlus struct {
	mixins.NatPlus[*NPlus, *NatPlus]
	V *BigInt
}

func NewNatPlus(v uint64) *NatPlus {
	self := &NatPlus{
		V: new(BigInt).SetUint64(v),
	}
	self.NatPlus = mixins.NewNatPlus(self)
	return self
}

func (n *NatPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return NewUnsignedPositiveArithmetic[*NatPlus](-1, false)
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

func (n *NatPlus) New(x *BigInt) *NatPlus {
	out := &NatPlus{
		V: x,
	}
	out.NatPlus = mixins.NewNatPlus(out)
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
	return n.New(new(BigInt).SetNat(v))
}

func (n *NatPlus) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   nplusName,
		Number: n.V,
	})
}

func (n *NatPlus) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Number *BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != Name {
		return errs.NewType("name (%s) must be (%s)", temp.Name, nplusName)
	}
	if temp.Number.Cmp(One) == algebra.LessThan {
		return errs.NewValue("number is not a natplus")
	}
	n.V = temp.Number
	n.NatPlus = mixins.NewNatPlus(n)
	return nil
}

var _ integer.NPlus[*NPlus, *NatPlus] = (*NPlus)(nil)
var _ mixins.HolesNaturalPreSemiRing[*NPlus, *NatPlus] = (*NPlus)(nil)
var _ mixins.HolesNPlus[*NPlus, *NatPlus] = (*NPlus)(nil)

type NPlus struct {
	mixins.NPlus[*NPlus, *NatPlus]
}

func (np *NPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return NewUnsignedPositiveArithmetic[*NatPlus](-1, false)
}

func (np *NPlus) Name() string {
	return nplusName
}

func (np *NPlus) Unwrap() *NPlus {
	return np
}

func (np *NPlus) domain() algebra.Set[*NatPlus] {
	return np.Element().Structure()
}

func (np *NPlus) Successor() algebra.Successor[*NatPlus] {
	return integer.NewSuccessorOperator(np.Arithmetic(), np.domain)
}

func (np *NPlus) Element() *NatPlus {
	return np.One()
}

func (np *NPlus) New(v uint64) *NatPlus {
	return NewNatPlus(v)
}
