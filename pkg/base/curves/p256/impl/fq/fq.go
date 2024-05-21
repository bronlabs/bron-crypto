package fq

import (
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
)

const (
	p256SatFieldLimbs = limb4.FieldLimbs + 1
	p256FieldBytes    = limb4.FieldBytes
	p256FieldBits     = 256
	p256DivSteps      = ((49 * p256FieldBits) + 57) / 17
)

var (
	p256FqInitOnce sync.Once
	p256FqParams   limb4.FieldParams
)

func New() *limb4.FieldValue {
	return &limb4.FieldValue{
		Value:      [limb4.FieldLimbs]uint64{},
		Params:     getP256FqParams(),
		Arithmetic: Arithmetic{},
	}
}

func p256FqParamsInit() {
	var r, r2, r3 [limb4.FieldLimbs]uint64
	var mod [p256SatFieldLimbs]uint64
	var modBytes [p256FieldBytes]byte

	SetOne((*MontgomeryDomainFieldElement)(&r))
	ToMontgomery((*MontgomeryDomainFieldElement)(&r2), (*NonMontgomeryDomainFieldElement)(&r))
	ToMontgomery((*MontgomeryDomainFieldElement)(&r3), (*NonMontgomeryDomainFieldElement)(&r2))
	Msat((*[5]uint64)(mod[:]))
	ToBytes(&modBytes, (*[4]uint64)(mod[:limb4.FieldLimbs]))
	slices.Reverse(modBytes[:])
	modulus := saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modBytes[:]))

	p256FqParams = limb4.FieldParams{
		R:            r,
		R2:           r2,
		R3:           r3,
		ModulusLimbs: [4]uint64(mod[:limb4.FieldLimbs]),
		Modulus:      modulus,
	}
}

func getP256FqParams() *limb4.FieldParams {
	p256FqInitOnce.Do(p256FqParamsInit)
	return &p256FqParams
}

// Arithmetic is a struct with all the methods needed for working
// in mod q.
type Arithmetic struct{}

// ToMontgomery converts this field to montgomery form.
func (Arithmetic) ToMontgomery(out, arg *[limb4.FieldLimbs]uint64) {
	ToMontgomery((*MontgomeryDomainFieldElement)(out), (*NonMontgomeryDomainFieldElement)(arg))
}

// FromMontgomery converts this field from montgomery form.
func (Arithmetic) FromMontgomery(out, arg *[limb4.FieldLimbs]uint64) {
	FromMontgomery((*NonMontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Neg performs modular negation.
func (Arithmetic) Neg(out, arg *[limb4.FieldLimbs]uint64) {
	Opp((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Square performs modular square.
func (Arithmetic) Square(out, arg *[limb4.FieldLimbs]uint64) {
	Square((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Mul performs modular multiplication.
func (Arithmetic) Mul(out, arg1, arg2 *[limb4.FieldLimbs]uint64) {
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Add performs modular addition.
func (Arithmetic) Add(out, arg1, arg2 *[limb4.FieldLimbs]uint64) {
	Add((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sub performs modular subtraction.
func (Arithmetic) Sub(out, arg1, arg2 *[limb4.FieldLimbs]uint64) {
	Sub((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sqrt performs modular square root.
func (f Arithmetic) Sqrt(wasSquare *uint64, out, arg *[limb4.FieldLimbs]uint64) {
	// See sqrt_ts_ct at
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-I.4
	// c1 := s
	// c2 := (q - 1) / (2^c1)
	// c2 := [4]uint64{
	//	0x4f3b9cac2fc63255,
	//	0xfbce6faada7179e8,
	//	0x0fffffffffffffff,
	//	0x0ffffffff0000000,
	// }
	// c3 := (c2 - 1) / 2
	c3 := [limb4.FieldLimbs]uint64{
		0x279dce5617e3192a,
		0xfde737d56d38bcf4,
		0x07ffffffffffffff,
		0x07fffffff8000000,
	}
	// c4 := generator
	// c5 := new(Fq).pow(generator, c2)
	c5 := [limb4.FieldLimbs]uint64{0x1015708f7e368fe1, 0x31c6c5456ecc4511, 0x5281fe8998a19ea1, 0x0279089e10c63fe8}
	var z, t, b, c, tv [limb4.FieldLimbs]uint64

	limb4.Pow(&z, arg, &c3, getP256FqParams(), f)
	Square((*MontgomeryDomainFieldElement)(&t), (*MontgomeryDomainFieldElement)(&z))
	Mul((*MontgomeryDomainFieldElement)(&t), (*MontgomeryDomainFieldElement)(&t), (*MontgomeryDomainFieldElement)(arg))
	Mul((*MontgomeryDomainFieldElement)(&z), (*MontgomeryDomainFieldElement)(&z), (*MontgomeryDomainFieldElement)(arg))

	copy(b[:], t[:])
	copy(c[:], c5[:])

	for i := s; i >= 2; i-- {
		for j := 1; j <= i-2; j++ {
			Square((*MontgomeryDomainFieldElement)(&b), (*MontgomeryDomainFieldElement)(&b))
		}
		// if b == 1 flag = 0 else flag = 1
		flag := -(&limb4.FieldValue{
			Value:      b,
			Params:     getP256FqParams(),
			Arithmetic: f,
		}).IsOne() + 1
		Mul((*MontgomeryDomainFieldElement)(&tv), (*MontgomeryDomainFieldElement)(&z), (*MontgomeryDomainFieldElement)(&c))
		Selectznz(&z, uint1(flag), &z, &tv)
		Square((*MontgomeryDomainFieldElement)(&c), (*MontgomeryDomainFieldElement)(&c))
		Mul((*MontgomeryDomainFieldElement)(&tv), (*MontgomeryDomainFieldElement)(&t), (*MontgomeryDomainFieldElement)(&c))
		Selectznz(&t, uint1(flag), &t, &tv)
		copy(b[:], t[:])
	}
	Square((*MontgomeryDomainFieldElement)(&c), (*MontgomeryDomainFieldElement)(&z))
	*wasSquare = (&limb4.FieldValue{
		Value:      c,
		Params:     getP256FqParams(),
		Arithmetic: f,
	}).Equal(&limb4.FieldValue{
		Value:      *arg,
		Params:     getP256FqParams(),
		Arithmetic: f,
	})
	Selectznz(out, uint1(*wasSquare), out, &z)
}

// Invert performs modular inverse.
func (Arithmetic) Invert(wasInverted *uint64, out, arg *[limb4.FieldLimbs]uint64) {
	var precomp [limb4.FieldLimbs]uint64
	DivstepPrecomp(&precomp)

	d := uint64(1)
	var f, g [p256SatFieldLimbs]uint64
	var v, r, out4, out5 [limb4.FieldLimbs]uint64
	var out1 uint64
	var out2, out3 [p256SatFieldLimbs]uint64

	FromMontgomery((*NonMontgomeryDomainFieldElement)(g[:]), (*MontgomeryDomainFieldElement)(arg))
	Msat(&f)
	SetOne((*MontgomeryDomainFieldElement)(&r))

	for i := 0; i < p256DivSteps-(p256DivSteps%2); i += 2 {
		Divstep(&out1, &out2, &out3, &out4, &out5, d, &f, &g, &v, &r)
		Divstep(&d, &f, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}
	if (p256DivSteps % 2) != 0 { // compile time if - always true
		Divstep(&out1, &out2, &out3, &out4, &out5, d, &f, &g, &v, &r)
		v = out4
		f = out2
	}

	var h [limb4.FieldLimbs]uint64
	Opp((*MontgomeryDomainFieldElement)(&h), (*MontgomeryDomainFieldElement)(&v))
	Selectznz(&v, uint1(f[p256SatFieldLimbs-1]>>63), &v, &h)
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(&v), (*MontgomeryDomainFieldElement)(&precomp))

	inverted := uint64(0)
	Nonzero(&inverted, out)
	*wasInverted = (inverted | -inverted) >> 63
}

// FromBytes converts a little endian byte array into a field element.
func (Arithmetic) FromBytes(out *[limb4.FieldLimbs]uint64, arg *[base.FieldBytes]byte) {
	FromBytes(out, arg)
}

// ToBytes converts a field element to a little endian byte array.
func (Arithmetic) ToBytes(out *[base.FieldBytes]byte, arg *[limb4.FieldLimbs]uint64) {
	ToBytes(out, arg)
}

// Selectznz performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (Arithmetic) Selectznz(out, arg1, arg2 *[limb4.FieldLimbs]uint64, choice uint64) {
	Selectznz(out, uint1(choice), arg1, arg2)
}

func (Arithmetic) Nonzero(out *uint64, arg *[limb4.FieldLimbs]uint64) {
	t := uint64(0)
	Nonzero(&t, arg)
	*out = (t | -t) >> 63
}

func (Arithmetic) SetOne(out *[limb4.FieldLimbs]uint64) {
	SetOne((*MontgomeryDomainFieldElement)(out))
}

// generator = 7 mod q is a generator of the `q - 1` order multiplicative
// subgroup, or in other words a primitive element of the field.
// generator^t where t * 2^s + 1 = q.
var generator = &[limb4.FieldLimbs]uint64{0x55eb74ab1949fac9, 0xd5af25406e5aaa5d, 0x0000000000000001, 0x00000006fffffff9}

// s satisfies the equation 2^s * t = q - 1 with t odd.
var s = 4

// rootOfUnity.
var rootOfUnity = &[limb4.FieldLimbs]uint64{0x0592d7fbb41e6602, 0x1546cad004378daf, 0xba807ace842a3dfc, 0xffc97f062a770992}
