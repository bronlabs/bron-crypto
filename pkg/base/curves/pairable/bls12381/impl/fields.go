//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab" --type Fp --sqrt sqrt
//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001" --type Fq --sqrt sqrt
package impl

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

var (
	_ fieldsImpl.QuadraticFieldExtensionArithmetic[*Fp]  = fp2Params{}
	_ fieldsImpl.CubicFieldExtensionArithmetic[*Fp2]     = fp6Params{}
	_ fieldsImpl.QuadraticFieldExtensionArithmetic[*Fp6] = fp12Params{}
)

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

func sqrt[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any](out, x, rootOfUnity *F, e uint64, progenitorExp []uint8) (ok ct.Bool) {
	return fieldsImpl.TonelliShanks[FP, F](out, x, rootOfUnity, e, progenitorExp)
}
