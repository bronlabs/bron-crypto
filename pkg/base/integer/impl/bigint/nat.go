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

var nName = fmt.Sprintf("%s_N", Name)

var _ integer.Nat[*N, *Nat] = (*Nat)(nil)
var _ integer.NaturalSemiRingElement[*N, *Nat] = (*Nat)(nil)
var _ mixins.HolesNat[*N, *Nat] = (*Nat)(nil)
var _ aimpl.ImplAdapter[*Nat, *BigInt] = (*Nat)(nil)
var _ integer.Number[*Nat] = (*Nat)(nil)

type Nat struct {
	mixins.Nat_[*N, *Nat]
	V *BigInt
}

func NewNat(v uint64) *Nat {
	self := &Nat{
		V: new(BigInt).SetUint64(v),
	}
	self.Nat_ = mixins.NewNat_(self)
	return self
}

func (n *Nat) Arithmetic() integer.Arithmetic[*Nat] {
	return NewUnsignedArithmetic[*Nat](-1, false)
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

func (n *Nat) Impl() *BigInt {
	return n.V
}

func (n *Nat) New(x *BigInt) *Nat {
	out := &Nat{
		V: x,
	}
	out.Nat_ = mixins.NewNat_(out)
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
	return n.New(new(BigInt).SetNat(v))
}

func (n *Nat) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   Name,
		Number: n.V,
	})
}

func (n *Nat) UnmarshalJSON(data []byte) error {
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
	if temp.Number.Cmp(Zero) == algebra.LessThan {
		return errs.NewValue("number is not a nat")
	}
	n.V = temp.Number
	n.Nat_ = mixins.NewNat_(n)
	return nil
}

var _ integer.N[*N, *Nat] = (*N)(nil)
var _ mixins.HolesN[*N, *Nat] = (*N)(nil)

type N struct {
	mixins.N[*N, *Nat]
}

func (np *N) Name() string {
	return nName
}

func (np *N) Arithmetic() integer.Arithmetic[*Nat] {
	return NewUnsignedArithmetic[*Nat](-1, false)
}

func (np *N) Unwrap() *N {
	return np
}

func (np *N) domain() algebra.Set[*Nat] {
	return np.Element().Structure()
}

func (np *N) Successor() algebra.Successor[*Nat] {
	return integer.NewSuccessorOperator(np.Arithmetic(), np.domain)
}

func (np *N) Element() *Nat {
	return np.One()
}

func (np *N) New(v uint64) *Nat {
	return nil
}
