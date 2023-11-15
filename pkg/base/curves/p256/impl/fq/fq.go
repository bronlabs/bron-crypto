package fq

import (
	"encoding/hex"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
)

const (
	p256GroupModulusHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
)

var (
	p256FqInitonce sync.Once
	p256FqParams   impl.FieldParams
)

func New() *impl.FieldValue {
	return &impl.FieldValue{
		Value:      [impl.FieldLimbs]uint64{},
		Params:     getP256FqParams(),
		Arithmetic: p256FqArithmetic{},
	}
}

func p256FqParamsInit() {
	modulusBytes, err := hex.DecodeString(p256GroupModulusHex)
	if err != nil {
		// this should never happen, string is known constant at compile time to be correct
		panic(err)
	}
	modulus := saferith.ModulusFromBytes(modulusBytes)

	// See FIPS 186-3, section D.2.3
	p256FqParams = impl.FieldParams{
		R:            [impl.FieldLimbs]uint64{0x0c46353d039cdaaf, 0x4319055258e8617b, 0x0000000000000000, 0x00000000ffffffff},
		R2:           [impl.FieldLimbs]uint64{0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59, 0x66e12d94f3d95620},
		R3:           [impl.FieldLimbs]uint64{0xac8ebec90b65a624, 0x111f28ae0c0555c9, 0x2543b9246ba5e93f, 0x503a54e76407be65},
		ModulusLimbs: [impl.FieldLimbs]uint64{0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000},
		Modulus:      modulus,
	}
}

func getP256FqParams() *impl.FieldParams {
	p256FqInitonce.Do(p256FqParamsInit)
	return &p256FqParams
}

// p256FqArithmetic is a struct with all the methods needed for working
// in mod q.
type p256FqArithmetic struct{}

// ToMontgomery converts this field to montgomery form.
func (p256FqArithmetic) ToMontgomery(out, arg *[impl.FieldLimbs]uint64) {
	ToMontgomery((*MontgomeryDomainFieldElement)(out), (*NonMontgomeryDomainFieldElement)(arg))
}

// FromMontgomery converts this field from montgomery form.
func (p256FqArithmetic) FromMontgomery(out, arg *[impl.FieldLimbs]uint64) {
	FromMontgomery((*NonMontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Neg performs modular negation.
func (p256FqArithmetic) Neg(out, arg *[impl.FieldLimbs]uint64) {
	Opp((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Square performs modular square.
func (p256FqArithmetic) Square(out, arg *[impl.FieldLimbs]uint64) {
	Square((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Mul performs modular multiplication.
func (p256FqArithmetic) Mul(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Add performs modular addition.
func (p256FqArithmetic) Add(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Add((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sub performs modular subtraction.
func (p256FqArithmetic) Sub(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Sub((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sqrt performs modular square root.
func (f p256FqArithmetic) Sqrt(wasSquare *int, out, arg *[impl.FieldLimbs]uint64) {
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
	c3 := [impl.FieldLimbs]uint64{
		0x279dce5617e3192a,
		0xfde737d56d38bcf4,
		0x07ffffffffffffff,
		0x07fffffff8000000,
	}
	// c4 := generator
	// c5 := new(Fq).pow(generator, c2)
	c5 := [impl.FieldLimbs]uint64{0x1015708f7e368fe1, 0x31c6c5456ecc4511, 0x5281fe8998a19ea1, 0x0279089e10c63fe8}
	var z, t, b, c, tv [impl.FieldLimbs]uint64

	impl.Pow(&z, arg, &c3, getP256FqParams(), f)
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
		flag := -(&impl.FieldValue{
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
	*wasSquare = (&impl.FieldValue{
		Value:      c,
		Params:     getP256FqParams(),
		Arithmetic: f,
	}).Equal(&impl.FieldValue{
		Value:      *arg,
		Params:     getP256FqParams(),
		Arithmetic: f,
	})
	Selectznz(out, uint1(*wasSquare), out, &z)
}

// Invert performs modular inverse.
func (f p256FqArithmetic) Invert(wasInverted *int, out, arg *[impl.FieldLimbs]uint64) {
	// Using an addition chain from
	// https://briansmith.org/ecc-inversion-addition-chains-01#p256_field_inversion
	var x1, x10, x11, x101, x111, x1010, x1111, x10101, x101010, x101111 [impl.FieldLimbs]uint64
	var x6, x8, x16, x32, tmp [impl.FieldLimbs]uint64

	copy(x1[:], arg[:])
	impl.Pow2k(&x10, arg, 1, f)
	Mul((*MontgomeryDomainFieldElement)(&x11), (*MontgomeryDomainFieldElement)(&x10), (*MontgomeryDomainFieldElement)(&x1))
	Mul((*MontgomeryDomainFieldElement)(&x101), (*MontgomeryDomainFieldElement)(&x10), (*MontgomeryDomainFieldElement)(&x11))
	Mul((*MontgomeryDomainFieldElement)(&x111), (*MontgomeryDomainFieldElement)(&x10), (*MontgomeryDomainFieldElement)(&x101))
	impl.Pow2k(&x1010, &x101, 1, f)
	Mul((*MontgomeryDomainFieldElement)(&x1111), (*MontgomeryDomainFieldElement)(&x101), (*MontgomeryDomainFieldElement)(&x1010))
	impl.Pow2k(&x10101, &x1010, 1, f)
	Mul((*MontgomeryDomainFieldElement)(&x10101), (*MontgomeryDomainFieldElement)(&x10101), (*MontgomeryDomainFieldElement)(&x1))
	impl.Pow2k(&x101010, &x10101, 1, f)
	Mul((*MontgomeryDomainFieldElement)(&x101111), (*MontgomeryDomainFieldElement)(&x101), (*MontgomeryDomainFieldElement)(&x101010))

	Mul((*MontgomeryDomainFieldElement)(&x6), (*MontgomeryDomainFieldElement)(&x10101), (*MontgomeryDomainFieldElement)(&x101010))

	impl.Pow2k(&x8, &x6, 2, f)
	Mul((*MontgomeryDomainFieldElement)(&x8), (*MontgomeryDomainFieldElement)(&x8), (*MontgomeryDomainFieldElement)(&x11))

	impl.Pow2k(&x16, &x8, 8, f)
	Mul((*MontgomeryDomainFieldElement)(&x16), (*MontgomeryDomainFieldElement)(&x16), (*MontgomeryDomainFieldElement)(&x8))

	impl.Pow2k(&x32, &x16, 16, f)
	Mul((*MontgomeryDomainFieldElement)(&x32), (*MontgomeryDomainFieldElement)(&x32), (*MontgomeryDomainFieldElement)(&x16))

	impl.Pow2k(&tmp, &x32, 64, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x32))

	impl.Pow2k(&tmp, &tmp, 32, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x32))

	impl.Pow2k(&tmp, &tmp, 6, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101111))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x111))

	impl.Pow2k(&tmp, &tmp, 4, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x11))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1111))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x10101))

	impl.Pow2k(&tmp, &tmp, 4, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101))

	impl.Pow2k(&tmp, &tmp, 3, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101))

	impl.Pow2k(&tmp, &tmp, 3, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x111))

	impl.Pow2k(&tmp, &tmp, 9, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101111))

	impl.Pow2k(&tmp, &tmp, 6, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1111))

	impl.Pow2k(&tmp, &tmp, 2, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1))

	impl.Pow2k(&tmp, &tmp, 6, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1111))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x111))

	impl.Pow2k(&tmp, &tmp, 4, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x111))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x111))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101))

	impl.Pow2k(&tmp, &tmp, 3, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x11))

	impl.Pow2k(&tmp, &tmp, 10, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x101111))

	impl.Pow2k(&tmp, &tmp, 2, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x11))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x11))

	impl.Pow2k(&tmp, &tmp, 5, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x11))

	impl.Pow2k(&tmp, &tmp, 3, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1))

	impl.Pow2k(&tmp, &tmp, 7, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x10101))

	impl.Pow2k(&tmp, &tmp, 6, f)
	Mul((*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&tmp), (*MontgomeryDomainFieldElement)(&x1111))

	*wasInverted = (&impl.FieldValue{
		Value:      *arg,
		Params:     getP256FqParams(),
		Arithmetic: f,
	}).IsNonZero()
	Selectznz(out, uint1(*wasInverted), out, &tmp)
}

// FromBytes converts a little endian byte array into a field element.
func (p256FqArithmetic) FromBytes(out *[impl.FieldLimbs]uint64, arg *[base.FieldBytes]byte) {
	FromBytes(out, arg)
}

// ToBytes converts a field element to a little endian byte array.
func (p256FqArithmetic) ToBytes(out *[base.FieldBytes]byte, arg *[impl.FieldLimbs]uint64) {
	ToBytes(out, arg)
}

// Selectznz performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (p256FqArithmetic) Selectznz(out, arg1, arg2 *[impl.FieldLimbs]uint64, choice int) {
	Selectznz(out, uint1(choice), arg1, arg2)
}

// generator = 7 mod q is a generator of the `q - 1` order multiplicative
// subgroup, or in other words a primitive element of the field.
// generator^t where t * 2^s + 1 = q.
var generator = &[impl.FieldLimbs]uint64{0x55eb74ab1949fac9, 0xd5af25406e5aaa5d, 0x0000000000000001, 0x00000006fffffff9}

// s satisfies the equation 2^s * t = q - 1 with t odd.
var s = 4

// rootOfUnity.
var rootOfUnity = &[impl.FieldLimbs]uint64{0x0592d7fbb41e6602, 0x1546cad004378daf, 0xba807ace842a3dfc, 0xffc97f062a770992}
