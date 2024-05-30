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

var zpName = fmt.Sprintf("%s_Zp", Name)

var (
	_ integer.Zp[*Zp, *IntP]     = (*Zp)(nil)
	_ mixins.HolesZp[*Zp, *IntP] = (*Zp)(nil)
)

type Zp struct {
	mixins.Zp[*Zp, *IntP]
	arithmetic integer.ModularArithmetic[*IntP]
}

func NewZp(modulus *NatPlus) (*Zp, error) {
	arithmetic, err := zpArithmetic(modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce Zp arithmetic")
	}
	instance := &Zp{
		arithmetic: arithmetic,
	}
	instance.Zp = mixins.NewZp(arithmetic, instance)
	return instance, nil
}

func (z *Zp) Cardinality() *saferith.Modulus {
	return z.Modulus()
}

func (z *Zp) Characteristic() *saferith.Nat {
	return z.Cardinality().Nat()
}

func (z *Zp) Arithmetic() integer.Arithmetic[*IntP] {
	return z.ModularArithmetic()
}

func (z *Zp) ModularArithmetic() integer.ModularArithmetic[*IntP] {
	return z.arithmetic
}

func (*Zp) Name() string {
	return zpName
}

func (z *Zp) Unwrap() *Zp {
	return z
}
func (z *Zp) Modulus() *saferith.Modulus {
	return saferith.ModulusFromNat(z.ModularArithmetic().Modulus().Nat())
}

var (
	_ integer.IntP[*Zp, *IntP]         = (*IntP)(nil)
	_ mixins.HolesIntP[*Zp, *IntP]     = (*IntP)(nil)
	_ impl.ImplAdapter[*Uint, *BigInt] = (*Uint)(nil)
	_ integer.Number[*IntP]            = (*IntP)(nil)
)

type IntP struct {
	mixins.IntP[*Zp, *IntP]
	modulus *NatPlus
	V       *Nat
}

func (n *IntP) Structure() *Zp {
	structure, err := NewZp(n.modulus)
	if err != nil {
		panic(err)
	}
	return structure
}

func (n *IntP) Unwrap() *IntP {
	return n
}

func (n *IntP) Impl() *BigInt {
	return n.V.Impl()
}

func (n *IntP) GCD(x *IntP) (*IntP, error) {
	res, err := n.V.GCD(x.V)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute gcd")
	}
	out, err := wrapIntP(res, n.modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap output")
	}
	return out, nil
}

func (n *IntP) AnnouncedLen() int {
	return n.V.AnnouncedLen()
}

func (n *IntP) TrueLen() uint {
	return n.V.TrueLen()
}

func (n *IntP) Clone() *IntP {
	out, err := wrapIntP(n.V, n.modulus)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *IntP) Nat() *saferith.Nat {
	return nil
}

func (n *IntP) SetNat(v *saferith.Nat) *IntP {
	return nil
}

func (n *IntP) Arithmetic() integer.Arithmetic[*IntP] {
	return n.Structure().ModularArithmetic()
}

func (n *IntP) ModularArithmetic() integer.ModularArithmetic[*IntP] {
	return n.Structure().ModularArithmetic()
}

func (n *IntP) Bytes() []byte {
	return n.Impl().Bytes()
}

func (n *IntP) SetBytes(input []byte) (*IntP, error) {
	vb := n.Impl().SetBytes(input)
	v, err := wrapNat(vb)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap deserialized bigint into nat")
	}
	n, err = wrapIntP(v, n.modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap into intp")
	}
	return n, nil
}

func (n *IntP) SetBytesWide(input []byte) (*IntP, error) {
	return n.SetBytes(input)
}

func (n *IntP) MarshalJSON() ([]byte, error) {
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

func (n *IntP) UnmarshalJSON(data []byte) error {
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
	out, err := wrapIntP(temp.Value, temp.Modulus)
	if err != nil {
		return errs.WrapFailed(err, "wrapping failed")
	}
	n = out
	return nil
}

func zpArithmetic(modulus *NatPlus) (integer.ModularArithmetic[*IntP], error) {
	wrapIntP, err := makeIntPWrapperWithFixedModulus(modulus)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce uint wrapper")
	}
	out, err := NewModularArithmetic[*IntP](modulus, wrapIntP, false)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialize modular arithmetic")
	}
	return out, nil
}

func makeIntPWrapperWithFixedModulus(m *NatPlus) (func(x *BigInt) (*IntP, error), error) {
	if m == nil {
		return nil, errs.NewIsNil("modulus")
	}
	if algebra.IsLessThan(m, m.Structure().One()) {
		return nil, errs.NewValue("modulus < 1")
	}
	if !m.IsPrime() {
		return nil, errs.NewValue("modulus is not prime")
	}
	return func(x *BigInt) (*IntP, error) {
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
		out := &IntP{
			V:       xmWrapped,
			modulus: m,
		}
		out.IntP = mixins.NewIntP(out)
		return out, nil
	}, nil
}

func wrapIntP(x *Nat, m *NatPlus) (*IntP, error) {
	f, err := makeIntPWrapperWithFixedModulus(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap intp modulus")
	}
	out, err := f(x.Impl())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not wrap intp value")
	}
	return out, nil
}
