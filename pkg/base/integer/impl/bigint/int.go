package bigint

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
	"github.com/cronokirby/saferith"
)

var zName = fmt.Sprintf("%s_Z", Name)

var (
	_ integer.Z[*Z, *Int]     = (*Z)(nil)
	_ mixins.HolesZ[*Z, *Int] = (*Z)(nil)
)

var (
	zInitOnce sync.Once
	zInstance Z
)

type Z struct {
	mixins.Z[*Z, *Int]
}

func zInit() {
	arithmetic := intArithmetic()
	zInstance = Z{}
	zInstance.Z = mixins.NewZ(arithmetic, &zInstance)
}

func NewZ() *Z {
	zInitOnce.Do(zInit)
	return &zInstance
}

func (z *Z) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (*Z) Name() string {
	return zName
}

func (n *Z) Arithmetic() integer.Arithmetic[*Int] {
	return intArithmetic()
}

func (z *Z) Unwrap() *Z {
	return z
}

var (
	_ integer.Int[*Z, *Int]           = (*Int)(nil)
	_ mixins.HolesInt[*Z, *Int]       = (*Int)(nil)
	_ impl.ImplAdapter[*Int, *BigInt] = (*Int)(nil)
	_ integer.Number[*Int]            = (*Int)(nil)
)

type Int struct {
	mixins.Int_[*Z, *Int]
	V *BigInt
}

func (*Int) Structure() *Z {
	return NewZ()
}

func (n *Int) Unwrap() *Int {
	return n
}

func (n *Int) Impl() *BigInt {
	return n.V
}

func (n *Int) GCD(x *Int) (*Int, error) {
	return wrapInt(n.V.GCD(x.V))
}

func (n *Int) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *Int) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *Int) Clone() *Int {
	out, err := wrapInt(n.V)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *Int) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(n.V.V, -1)
}

func (n *Int) SetNat(v *saferith.Nat) *Int {
	out, err := wrapInt(new(BigInt).SetNat(v))
	if err != nil {
		panic(err)
	}
	n.V = out.V
	return n
}

func (n *Int) Int() *saferith.Int {
	return new(saferith.Int).SetBig(n.V.V, -1)
}

func (n *Int) SetInt(v *saferith.Int) *Int {
	out, err := wrapInt(new(BigInt).New(v.Big()))
	if err != nil {
		panic(err)
	}
	n.V = out.V
	return n
}

func (n *Int) Big() *big.Int {
	return n.V.V
}

func (n *Int) SetBig(v *big.Int) *Int {
	out, err := wrapInt(new(BigInt).New(v))
	if err != nil {
		panic(err)
	}
	n.V = out.V
	return n
}

func (n *Int) Arithmetic() integer.Arithmetic[*Int] {
	return intArithmetic()
}

func (n *Int) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name   string
		Number *BigInt
	}
	return json.Marshal(&temp{
		Name:   zName,
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
	if temp.Name != zName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, zName)
	}
	out, err := wrapInt(temp.Number)
	if err != nil {
		return errs.WrapFailed(err, "could not wrap bigint into int")
	}
	n = out
	return nil
}

func intArithmetic() integer.Arithmetic[*Int] {
	return NewSignedArithmetic[*Int](-1, wrapInt, false)
}

func wrapInt(x *BigInt) (*Int, error) {
	if x == nil {
		return nil, errs.NewIsNil("argument")
	}
	out := &Int{
		V: x,
	}
	out.Int_ = mixins.NewInt_(out)
	return out, nil
}
