package bigint

import (
	"encoding/json"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
	"github.com/cronokirby/saferith"
)

var znName = fmt.Sprintf("%s_Zn", Name)

var (
	_ integer.Zn[*Zn, *Uint]     = (*Zn)(nil)
	_ mixins.HolesZn[*Zn, *Uint] = (*Zn)(nil)
)

type Zn struct {
	mixins.Zn[*Zn, *Uint]
	arithmetic integer.ModularArithmetic[*Uint]
}

func NewZn(modulus *NatPlus) (*Zn, error) {
	arithmetic, err := znArithmetic(modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce Zn arithmetic")
	}
	instance := &Zn{
		arithmetic: arithmetic,
	}
	instance.Zn = mixins.NewZn(arithmetic, instance)
	return instance, nil
}

func NewZnPrimePower(primes, powers []*NatPlus) (*Zn, error) {
	panic("implement me")
}

func (z *Zn) Cardinality() *saferith.Modulus {
	return z.Modulus()
}

func (z *Zn) Characteristic() *saferith.Nat {
	return z.Cardinality().Nat()
}

func (z *Zn) Arithmetic() integer.Arithmetic[*Uint] {
	return z.ModularArithmetic()
}

func (z *Zn) ModularArithmetic() integer.ModularArithmetic[*Uint] {
	return z.arithmetic
}

func (*Zn) Name() string {
	return znName
}

func (z *Zn) Unwrap() *Zn {
	return z
}

func (z *Zn) Modulus() *saferith.Modulus {
	return saferith.ModulusFromNat(z.ModularArithmetic().Modulus().Nat())
}

var (
	_ integer.Uint[*Zn, *Uint]         = (*Uint)(nil)
	_ mixins.HolesUint[*Zn, *Uint]     = (*Uint)(nil)
	_ impl.ImplAdapter[*Uint, *BigInt] = (*Uint)(nil)
	_ integer.Number[*Uint]            = (*Uint)(nil)
)

type Uint struct {
	mixins.Uint[*Zn, *Uint]
	modulus *NatPlus
	V       *Nat
}

func (n *Uint) Structure() *Zn {
	structure, err := NewZn(n.modulus)
	if err != nil {
		panic(err)
	}
	return structure
}

func (n *Uint) Unwrap() *Uint {
	return n
}

func (n *Uint) GCD(x *Uint) (*Uint, error) {
	res, err := n.V.GCD(x.V)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute gcd")
	}
	out, err := wrapUint(res, n.modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap output")
	}
	return out, nil
}

func (n *Uint) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *Uint) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *Uint) Impl() *BigInt {
	return n.V.Impl()
}

func (n *Uint) Clone() *Uint {
	out, err := wrapUint(n.V, n.modulus)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *Uint) Nat() *saferith.Nat {
	return nil
}

func (n *Uint) SetNat(v *saferith.Nat) *Uint {
	return nil
}

func (n *Uint) Arithmetic() integer.Arithmetic[*Uint] {
	return n.Structure().ModularArithmetic()
}

func (n *Uint) ModularArithmetic() integer.ModularArithmetic[*Uint] {
	return n.Structure().ModularArithmetic()
}

func (n *Uint) Bytes() []byte {
	return n.Impl().Bytes()
}

func (n *Uint) SetBytes(input []byte) (*Uint, error) {
	vb := n.Impl().SetBytes(input)
	v, err := wrapNat(vb)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap deserialized bigint into nat")
	}
	n, err = wrapUint(v, n.modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap into uint")
	}
	return n, nil
}

func (n *Uint) SetBytesWide(input []byte) (*Uint, error) {
	return n.SetBytes(input)
}

func (n *Uint) MarshalJSON() ([]byte, error) {
	type temp struct {
		Name    string
		Value   *Nat
		Modulus *NatPlus
	}
	return json.Marshal(&temp{
		Name:    znName,
		Value:   n.V,
		Modulus: n.modulus,
	})
}

func (n *Uint) UnmarshalJSON(data []byte) error {
	var temp struct {
		Name    string
		Value   *Nat
		Modulus *NatPlus
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal json")
	}
	if temp.Name != znName {
		return errs.NewType("name (%s) must be (%s)", temp.Name, znName)
	}
	out, err := wrapUint(temp.Value, temp.Modulus)
	if err != nil {
		return errs.WrapFailed(err, "wrapping failed")
	}
	n = out
	return nil
}

func znArithmetic(modulus *NatPlus) (integer.ModularArithmetic[*Uint], error) {
	wrapUint, err := makeUintWrapperWithFixedModulus(modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce uint wrapper")
	}
	out, err := NewModularArithmetic[*Uint](modulus, wrapUint, false)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialize modular arithmetic")
	}
	return out, nil
}

func makeUintWrapperWithFixedModulus(m *NatPlus) (func(x *BigInt) (*Uint, error), error) {
	if m == nil {
		return nil, errs.NewIsNil("modulus")
	}
	if algebra.IsLessThan(m, m.Structure().One()) {
		return nil, errs.NewValue("modulus < 1")
	}
	return func(x *BigInt) (*Uint, error) {
		if x == nil {
			return nil, errs.NewIsNil("argument")
		}
		xm, err := x.Mod(m.Impl())
		if err != nil {
			return nil, errs.WrapFailed(err, "could not compute x mod m")
		}
		xmWrapped, err := wrapNat(xm)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not wrap x mod m into nat")
		}
		out := &Uint{
			V:       xmWrapped,
			modulus: m,
		}
		out.Uint = mixins.NewUint(out)
		return out, nil
	}, nil
}

func wrapUint(x *Nat, m *NatPlus) (*Uint, error) {
	f, err := makeUintWrapperWithFixedModulus(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap uint modulus")
	}
	out, err := f(x.Impl())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap uint value")
	}
	return out, nil
}
