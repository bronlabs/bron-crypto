package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/field/impl"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/cronokirby/saferith"
)

var _ integer.Zp[*Zp, *IntP] = (*Zp)(nil)
var _ impl.HolesZp[*Zp, *IntP] = (*Zp)(nil)

type Zp struct {
	impl.Zp_[*Zp, *IntP]
}

func (z *Zp) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (z *Zp) Characteristic() *saferith.Nat {
	// TODO: represent inf
	return z.Cardinality().Nat()
}

func (z *Zp) Arithmetic() integer.Arithmetic[*IntP] {
	return z.ModularArithmetic()
}

func (z *Zp) ModularArithmetic() integer.ModularArithmetic[*IntP] {
	modulus := new(IntP).New(bg.New(z.Cardinality().Big()))
	out, err := bg.NewModularArithmetic[*IntP](modulus, -1, false)
	if err != nil {
		panic(errs.WrapFailed(err, "could not initialize modular arithmetic"))
	}
	return out
}

func (*Zp) Name() string {
	return zpName
}

func (z *Zp) Element() *IntP {
	return z.One()
}

func (z *Zp) New(v uint64) *IntP {
	return nil
}

func (z *Zp) Unwrap() *Zp {
	return z
}
