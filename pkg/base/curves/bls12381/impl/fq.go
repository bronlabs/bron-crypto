package bls12381impl

import (
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/arithmetic/limb4"
)

const (
	fqFieldBits = 255
	fqDivSteps  = ((49 * fqFieldBits) + 57) / 17

	// 2^S * t = MODULUS - 1 with t odd.
	fqS = 32
)

var (
	bls12381FqInitOnce sync.Once
	bls12381FqParams   limb4.FieldParams

	// fqGenerator = 7 (multiplicative fqGenerator of r-1 order, that is also quadratic nonresidue).
	fqGenerator = [limb4.FieldLimbs]uint64{0x0000000efffffff1, 0x17e363d300189c0f, 0xff9c57876f8457b0, 0x351332208fc5a8c4}
	FqModulus   = getBls12381FqParams().Modulus
)

func FqNew() *limb4.FieldValue {
	return &limb4.FieldValue{
		Value:      [limb4.FieldLimbs]uint64{},
		Params:     getBls12381FqParams(),
		Arithmetic: bls12381FqArithmetic{},
	}
}

func bls12381FqParamsInit() {
	var r, r2, r3 [limb4.FieldLimbs]uint64
	var modulusLimbs [limb4.FieldLimbs + 1]uint64
	var modulusBytes [limb4.FieldBytes]byte

	fiatFqSetOne((*fiatFqMontgomeryDomainFieldElement)(&r))
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(&r2), (*fiatFqNonMontgomeryDomainFieldElement)(&r))
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(&r3), (*fiatFqNonMontgomeryDomainFieldElement)(&r2))
	fiatFqMsat(&modulusLimbs)
	fiatFqToBytes(&modulusBytes, (*[limb4.FieldLimbs]uint64)(modulusLimbs[:limb4.FieldLimbs]))
	slices.Reverse(modulusBytes[:])
	modulus := saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modulusBytes[:]).Resize(fqFieldBits))

	bls12381FqParams = limb4.FieldParams{
		R:            r,
		R2:           r2,
		R3:           r3,
		ModulusLimbs: [4]uint64(modulusLimbs[:limb4.FieldLimbs]),
		Modulus:      modulus,
	}
}

func getBls12381FqParams() *limb4.FieldParams {
	bls12381FqInitOnce.Do(bls12381FqParamsInit)
	return &bls12381FqParams
}

// bls12381FqArithmetic is a struct with all the methods needed for working
// in mod q.
type bls12381FqArithmetic struct{}

// ToMontgomery converts this field to montgomery form.
func (bls12381FqArithmetic) ToMontgomery(out, arg *[limb4.FieldLimbs]uint64) {
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqNonMontgomeryDomainFieldElement)(arg))
}

// FromMontgomery converts this field from montgomery form.
func (bls12381FqArithmetic) FromMontgomery(out, arg *[limb4.FieldLimbs]uint64) {
	fiatFqFromMontgomery((*fiatFqNonMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(arg))
}

// Neg performs modular negation.
func (bls12381FqArithmetic) Neg(out, arg *[limb4.FieldLimbs]uint64) {
	fiatFqOpp((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(arg))
}

// Square performs modular square.
func (bls12381FqArithmetic) Square(out, arg *[limb4.FieldLimbs]uint64) {
	fiatFqSquare((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(arg))
}

// Mul performs modular multiplication.
func (bls12381FqArithmetic) Mul(out, arg1, arg2 *[limb4.FieldLimbs]uint64) {
	fiatFqMul((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(arg1), (*fiatFqMontgomeryDomainFieldElement)(arg2))
}

// Add performs modular addition.
func (bls12381FqArithmetic) Add(out, arg1, arg2 *[limb4.FieldLimbs]uint64) {
	fiatFqAdd((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(arg1), (*fiatFqMontgomeryDomainFieldElement)(arg2))
}

// Sub performs modular subtraction.
func (bls12381FqArithmetic) Sub(out, arg1, arg2 *[limb4.FieldLimbs]uint64) {
	fiatFqSub((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(arg1), (*fiatFqMontgomeryDomainFieldElement)(arg2))
}

// Sqrt performs modular square root.
func (f bls12381FqArithmetic) Sqrt(wasSquare *uint64, out, arg *[limb4.FieldLimbs]uint64) {
	// See sqrt_ts_ct at
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-I.4
	// c1 := fqS
	// c2 := (q - 1) / (2^c1)
	c2 := [4]uint64{
		0xfffe5bfeffffffff,
		0x09a1d80553bda402,
		0x299d7d483339d808,
		0x0000000073eda753,
	}
	// c3 := (c2 - 1) / 2
	c3 := [limb4.FieldLimbs]uint64{
		0x7fff2dff7fffffff,
		0x04d0ec02a9ded201,
		0x94cebea4199cec04,
		0x0000000039f6d3a9,
	}
	// c4 := fqGenerator
	var c5 [limb4.FieldLimbs]uint64
	limb4.Pow(&c5, &fqGenerator, &c2, getBls12381FqParams(), f)
	// c5 := [impl.FieldLimbs]uint64{0x1015708f7e368fe1, 0x31c6c5456ecc4511, 0x5281fe8998a19ea1, 0x0279089e10c63fe8}
	var z, t, b, c, tv [limb4.FieldLimbs]uint64

	limb4.Pow(&z, arg, &c3, getBls12381FqParams(), f)
	f.Square(&t, &z)
	f.Mul(&t, &t, arg)
	f.Mul(&z, &z, arg)

	copy(b[:], t[:])
	copy(c[:], c5[:])

	for i := fqS; i >= 2; i-- {
		for j := 1; j <= i-2; j++ {
			f.Square(&b, &b)
		}
		// if b == 1 flag = 0 else flag = 1
		flag := -(&limb4.FieldValue{
			Value:      b,
			Params:     getBls12381FqParams(),
			Arithmetic: f,
		}).IsOne() + 1
		f.Mul(&tv, &z, &c)
		f.Selectznz(&z, &z, &tv, flag)
		f.Square(&c, &c)
		f.Mul(&tv, &t, &c)
		f.Selectznz(&t, &t, &tv, flag)
		copy(b[:], t[:])
	}
	f.Square(&c, &z)
	*wasSquare = (&limb4.FieldValue{
		Value:      c,
		Params:     getBls12381FqParams(),
		Arithmetic: f,
	}).Equal(&limb4.FieldValue{
		Value:      *arg,
		Params:     getBls12381FqParams(),
		Arithmetic: f,
	})
	f.Selectznz(out, out, &z, *wasSquare)
}

// Invert performs modular inverse.
func (bls12381FqArithmetic) Invert(wasInverted *uint64, out, arg *[limb4.FieldLimbs]uint64) {
	var precomp [limb4.FieldLimbs]uint64
	fiatFqDivstepPrecomp(&precomp)

	d := uint64(1)
	var f, g [limb4.FieldLimbs + 1]uint64
	var v, r, out4, out5 [limb4.FieldLimbs]uint64
	var out1 uint64
	var out2, out3 [limb4.FieldLimbs + 1]uint64

	fiatFqFromMontgomery((*fiatFqNonMontgomeryDomainFieldElement)(g[:]), (*fiatFqMontgomeryDomainFieldElement)(arg))
	fiatFqMsat(&f)
	fiatFqSetOne((*fiatFqMontgomeryDomainFieldElement)(&r))

	for i := 0; i < fqDivSteps-(fqDivSteps%2); i += 2 {
		fiatFqDivstep(&out1, &out2, &out3, &out4, &out5, d, &f, &g, &v, &r)
		fiatFqDivstep(&d, &f, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}
	if (fqDivSteps % 2) != 0 { // compile time if - always true
		fiatFqDivstep(&out1, &out2, &out3, &out4, &out5, d, &f, &g, &v, &r)
		v = out4
		f = out2
	}

	var h [limb4.FieldLimbs]uint64
	fiatFqOpp((*fiatFqMontgomeryDomainFieldElement)(&h), (*fiatFqMontgomeryDomainFieldElement)(&v))
	fiatFqSelectznz(&v, fiatFqUint1(f[limb4.FieldLimbs]>>63), &v, &h)
	fiatFqMul((*fiatFqMontgomeryDomainFieldElement)(out), (*fiatFqMontgomeryDomainFieldElement)(&v), (*fiatFqMontgomeryDomainFieldElement)(&precomp))

	inverted := uint64(0)
	fiatFqNonzero(&inverted, out)
	*wasInverted = (inverted | -inverted) >> 63
}

// FromBytes converts a little endian byte array into a field element.
func (bls12381FqArithmetic) FromBytes(out *[limb4.FieldLimbs]uint64, arg *[base.FieldBytes]byte) {
	fiatFqFromBytes(out, arg)
}

// ToBytes converts a field element to a little endian byte array.
func (bls12381FqArithmetic) ToBytes(out *[base.FieldBytes]byte, arg *[limb4.FieldLimbs]uint64) {
	fiatFqToBytes(out, arg)
}

// Selectznz performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (bls12381FqArithmetic) Selectznz(out, arg1, arg2 *[limb4.FieldLimbs]uint64, choice uint64) {
	fiatFqSelectznz(out, fiatFqUint1(choice), arg1, arg2)
}

func (bls12381FqArithmetic) Nonzero(out *uint64, arg *[limb4.FieldLimbs]uint64) {
	var t uint64
	fiatFqNonzero(&t, arg)
	*out = (t | -t) >> 63
}

func (bls12381FqArithmetic) SetOne(out *[limb4.FieldLimbs]uint64) {
	fiatFqSetOne((*fiatFqMontgomeryDomainFieldElement)(out))
}
