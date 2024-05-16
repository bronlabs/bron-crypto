package bigint

import (
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
)

var _ mixins.HolesNat[*N, *Nat] = (*Nat)(nil)

// var _ integer.NatPlus[*NPlus, *NatPlus] = (*NatPlus)(nil)
// var _ aimpl.ImplAdapter[*NatPlus, *BigInt] = (*NatPlus)(nil)
// var _ integer.Number[*NatPlus] = (*NatPlus)(nil)

type Nat struct {
	mixins.Nat[*N, *Nat]
	V *BigInt
}

// func NewNatPlus(v uint64) *NatPlus {
// 	self := &NatPlus{
// 		V: new(BigInt).SetUint64(v),
// 	}
// 	self.NatPlus = mixins.NewNatPlus(self)
// 	return self
// }

func (n *Nat) Arithmetic() integer.Arithmetic[*Nat] {
	return NewUnsignedArithmetic[*Nat](-1, false)
}

// func (*NatPlus) Structure() *NPlus {
// 	return &NPlus{}
// }

// func (n *NatPlus) Unwrap() *NatPlus {
// 	return n
// }

func (n *Nat) Impl() *BigInt {
	return n.V
}

func (n *Nat) New(x *BigInt) *Nat {
	out := &Nat{
		V: x,
	}
	out.Nat = mixins.NewNat(out)
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

// func (n *NatPlus) Nat() *saferith.Nat {
// 	return new(saferith.Nat).SetBig(n.V.V, -1)
// }

// func (n *NatPlus) SetNat(v *saferith.Nat) *NatPlus {
// 	return n.New(new(BigInt).SetNat(v))
// }

func (n *Nat) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Type   integer.ArithmeticType
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   n.Arithmetic().Name(),
		Type:   integer.ForN,
		Number: n.V,
	})
}

func (n *NatPlus) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name   string
		Type   integer.ArithmeticType
		Number *BigInt
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if string(temp.Type) != string(integer.ForNPlus) {
		return errs.NewType("type (%s) must be (%s)", temp.Type, integer.ForN)
	}
	n.V = temp.Number
	n.Nat = mixins.NewNat(n)
	return nil
}

// var _ integer.NPlus[*NPlus, *NatPlus] = (*NPlus)(nil)
var _ mixins.HolesN[*N, *Nat] = (*N)(nil)

// var _ mixins.HolesNPlus[*NPlus, *NatPlus] = (*NPlus)(nil)

type N struct {
	mixins.N[*N, *Nat]
}

func (np *N) Name() string {
	return string(integer.ForN)
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
