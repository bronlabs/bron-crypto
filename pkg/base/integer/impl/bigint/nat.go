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

var natName = fmt.Sprintf("%s_N", Name)

var (
	_ integer.N[*N, *Nat]          = (*N)(nil)
	_ integer.NaturalRig[*N, *Nat] = (*N)(nil)
	_ mixins.HolesN[*N, *Nat]      = (*N)(nil)
)

var (
	nInitOnce sync.Once
	nInstance N
)

type N struct {
	mixins.N[*N, *Nat]
}

func nInit() {
	arithmetic := natArithmetic()
	nInstance = N{}
	nInstance.N = mixins.NewN(arithmetic, &nInstance)
}

func NewN() *N {
	nInitOnce.Do(nInit)
	return &nInstance
}

func (np *N) Name() string {
	return natName
}

func (np *N) Arithmetic() integer.Arithmetic[*Nat] {
	return natArithmetic()
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

var (
	_ integer.Nat[*N, *Nat]               = (*Nat)(nil)
	_ integer.NaturalRigElement[*N, *Nat] = (*Nat)(nil)
	_ mixins.HolesNat[*N, *Nat]           = (*Nat)(nil)
	_ impl.ImplAdapter[*Nat, *BigInt]     = (*Nat)(nil)
	_ integer.Number[*Nat]                = (*Nat)(nil)
)

type Nat struct {
	mixins.Nat_[*N, *Nat]
	V *BigInt
}

func (n *Nat) Arithmetic() integer.Arithmetic[*Nat] {
	return natArithmetic()
}

func (n *Nat) GCD(x *Nat) (*Nat, error) {
	return wrapNat(n.V.GCD(x.V))
}

func (*Nat) Structure() *N {
	return NewN()
}

func (n *Nat) Unwrap() *Nat {
	return n
}

func (n *Nat) Impl() *BigInt {
	return n.V
}

func (n *Nat) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *Nat) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *Nat) Clone() *Nat {
	out, err := wrapNat(n.V)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *Nat) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *Nat) SetNat(v *saferith.Nat) *Nat {
	res, err := wrapNat(new(BigInt).SetNat(v))
	if err != nil {
		panic(err)
	}
	n.V = res.V
	return n
}

func (n *Nat) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   natName,
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
	if temp.Name != natName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, natName)
	}
	out, err := wrapNat(temp.Number)
	if err != nil {
		return errs.WrapFailed(err, "could not wrap bigint into nat")
	}
	n = out
	return nil
}

func wrapNat(x *BigInt) (*Nat, error) {
	if x == nil {
		return nil, errs.NewIsNil("argument")
	}
	if algebra.IsLessThan(x, Zero) {
		return nil, errs.NewValue("x < 0")
	}
	out := &Nat{
		V: x,
	}
	out.Nat_ = mixins.NewNat_(out)
	return out, nil
}

func natArithmetic() integer.Arithmetic[*Nat] {
	return NewUnsignedArithmetic[*Nat](-1, wrapNat, false)
}
