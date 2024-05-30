package bigint

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
	"github.com/cronokirby/saferith"
)

var natPlusName = fmt.Sprintf("%s_N+", Name)

var (
	_ integer.NPlus[*NPlus, *NatPlus]               = (*NPlus)(nil)
	_ mixins.HolesNaturalSemiRing[*NPlus, *NatPlus] = (*NPlus)(nil)
	_ mixins.HolesNPlus[*NPlus, *NatPlus]           = (*NPlus)(nil)
)

var (
	nPlusInitOnce sync.Once
	nPlusInstance NPlus
)

type NPlus struct {
	mixins.NPlus[*NPlus, *NatPlus]
}

func nPlusInit() {
	arithmetic := natPlusArithmetic()
	nPlusInstance = NPlus{}
	nPlusInstance.NPlus = mixins.NewNPlus(arithmetic, &nPlusInstance)
}

func NewNPlus() *NPlus {
	nPlusInitOnce.Do(nPlusInit)
	return &nPlusInstance
}

func (np *NPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return natPlusArithmetic()
}

func (np *NPlus) Name() string {
	return natPlusName
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

var (
	_ integer.NatPlus[*NPlus, *NatPlus]                = (*NatPlus)(nil)
	_ integer.NaturalSemiRingElement[*NPlus, *NatPlus] = (*NatPlus)(nil)
	_ mixins.HolesNatPlus[*NPlus, *NatPlus]            = (*NatPlus)(nil)
	_ impl.ImplAdapter[*NatPlus, *BigInt]              = (*NatPlus)(nil)
	_ integer.Number[*NatPlus]                         = (*NatPlus)(nil)
)

type NatPlus struct {
	mixins.NatPlus[*NPlus, *NatPlus]
	V *BigInt
}

func (n *NatPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return natPlusArithmetic()
}

func (*NatPlus) Structure() *NPlus {
	return NewNPlus()
}

func (n *NatPlus) GCD(x *NatPlus) (*NatPlus, error) {
	return wrapNatPlus(n.V.GCD(x.V))
}

func (n *NatPlus) IsPrime() bool {
	nat, err := wrapNat(n.Impl())
	if err != nil {
		panic(err)
	}
	return nat.IsPrime()
}

func (n *NatPlus) Unwrap() *NatPlus {
	return n
}

func (n *NatPlus) Impl() *BigInt {
	return n.V
}

func (n *NatPlus) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *NatPlus) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *NatPlus) Clone() *NatPlus {
	out, err := wrapNatPlus(n.V)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *NatPlus) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *NatPlus) SetNat(v *saferith.Nat) *NatPlus {
	res, err := wrapNatPlus(new(BigInt).SetNat(v))
	if err != nil {
		panic(err)
	}
	n.V = res.V
	return n
}

func (n *NatPlus) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   Name,
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
	if temp.Name != natPlusName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, Name)
	}
	out, err := wrapNatPlus(temp.Number)
	if err != nil {
		return errs.WrapFailed(err, "could not wrap bigint into natPlus")
	}
	n = out
	return nil
}

func wrapNatPlus(x *BigInt) (*NatPlus, error) {
	if x == nil {
		return nil, errs.NewIsNil("argument")
	}
	if algebra.IsLessThan(x, One) {
		return nil, errs.NewValue("x < 1")
	}
	out := &NatPlus{
		V: x,
	}
	out.NatPlus = mixins.NewNatPlus(out)
	return out, nil
}

func natPlusArithmetic() integer.Arithmetic[*NatPlus] {
	return NewUnsignedPositiveArithmetic[*NatPlus](-1, wrapNatPlus, false)
}
