//go:generate go run ../../newimpl/fields/codegen pkg/base/curves/bls12381/newimpl
package impl

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381/impl/internal/fiat"
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

var (
	_ fieldsImpl.QuadraticFieldExtensionArith[*Fp]  = fp2Params{}
	_ fieldsImpl.CubicFieldExtensionArith[*Fp2]     = fp6Params{}
	_ fieldsImpl.QuadraticFieldExtensionArith[*Fp6] = fp12Params{}
)

//nolint:tagliatelle // embedded fields
type Fp struct {
	fieldsImpl.SqrtTrait[*Fp, Fp]       `fiat:"sqrt_trait"`
	fiat.FpMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab,primitive_element=2"`
}

//nolint:tagliatelle // embedded fields
type Fq struct {
	fieldsImpl.SqrtTrait[*Fq, Fq]       `fiat:"sqrt_trait"`
	fiat.FqMontgomeryDomainFieldElement `fiat:"word_by_word_montgomery,order=0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001,primitive_element=7"`
}

type Fp2 = fieldsImpl.QuadraticFieldExtensionImpl[*Fp, fp2Params, Fp]
type Fp6 = fieldsImpl.CubicFieldExtensionImpl[*Fp2, fp6Params, Fp2]
type Fp12 = fieldsImpl.QuadraticFieldExtensionImpl[*Fp6, fp12Params, Fp6]

type fp2Params struct{}
type fp6Params struct{}
type fp12Params struct{}

func (fp2Params) MulByQuadraticNonResidue(out, in *Fp) {
	out.Neg(in)
}

func (fp6Params) MulByCubicNonResidue(out, in *Fp2) {
	var params fp2Params
	var c Fp2

	c.U1.Add(&in.U0, &in.U1)
	params.MulByQuadraticNonResidue(&c.U0, &in.U1)
	c.U0.Add(&c.U0, &in.U0)

	out.Set(&c)
}

func (fp6Params) RootOfUnity(out *Fp2) {
	//TODO implement me
	panic("implement me")
}

func (fp6Params) ProgenitorExponent() []uint8 {
	//TODO implement me
	panic("implement me")
}

func (fp6Params) E() uint64 {
	return 6
}

func (fp12Params) MulByQuadraticNonResidue(out, in *Fp6) {
	var params fp6Params
	var c Fp6

	c.U2.Set(&in.U1)
	c.U1.Set(&in.U0)
	params.MulByCubicNonResidue(&c.U0, &in.U2)

	out.Set(&c)
}
