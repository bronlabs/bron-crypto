package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/uints/impl"
	"github.com/cronokirby/saferith"
)

var _ integer.Zn[*Zn, *Uint] = (*Zn)(nil)
var _ impl.HolesZn[*Zn, *Uint] = (*Zn)(nil)

type Zn struct {
	impl.Zn_[*Zn, *Uint]
}

func (z *Zn) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (z *Zn) Characteristic() *saferith.Nat {
	// TODO: represent inf
	return z.Cardinality().Nat()
}

func (z *Zn) Arithmetic() integer.Arithmetic[*Uint] {
	return z.ModularArithmetic()
}

func (z *Zn) ModularArithmetic() integer.ModularArithmetic[*Uint] {
	modulus := new(Uint).New(bg.New(z.Cardinality().Big()))
	out, err := bg.NewModularArithmetic[*Uint](modulus, -1, false)
	if err != nil {
		panic(errs.WrapFailed(err, "could not initialize modular arithmetic"))
	}
	return out
}

func (*Zn) Name() string {
	return Name
}

func (z *Zn) Element() *Uint {
	return z.One()
}

func (z *Zn) New(v uint64) *Uint {
	return nil
}

func (z *Zn) Unwrap() *Zn {
	return z
}
