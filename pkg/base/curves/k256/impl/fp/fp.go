package fp

import (
	"encoding/hex"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
)

const (
	k256FieldModulusHex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
)

var (
	k256FpInitonce sync.Once
	k256FpParams   limb4.FieldParams
)

func New() *limb4.FieldValue {
	return &limb4.FieldValue{
		Value:      [limb4.FieldLimbs]uint64{},
		Params:     getK256FpParams(),
		Arithmetic: Arithmetic{},
	}
}

func k256FpParamsInit() {
	modulusBytes, err := hex.DecodeString(k256FieldModulusHex)
	if err != nil {
		// this should never happen, string is known constant at compile time to be correct
		panic(err)
	}
	modulus := saferith.ModulusFromBytes(modulusBytes)

	k256FpParams = limb4.FieldParams{
		R:            [limb4.FieldLimbs]uint64{0x00000001000003d1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		R2:           [limb4.FieldLimbs]uint64{0x000007a2000e90a1, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000},
		R3:           [limb4.FieldLimbs]uint64{0x002bb1e33795f671, 0x0000000100000b73, 0x0000000000000000, 0x0000000000000000},
		ModulusLimbs: [limb4.FieldLimbs]uint64{0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
		Modulus:      modulus,
	}
}

func getK256FpParams() *limb4.FieldParams {
	k256FpInitonce.Do(k256FpParamsInit)
	return &k256FpParams
}

// Arithmetic is a struct with all the methods needed for working
// in mod p.
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
func (f Arithmetic) Sqrt(wasSquare *int, out, arg *[limb4.FieldLimbs]uint64) {
	// p is congruent to 3 mod 4 we can compute
	// sqrt using elem^(p+1)/4 mod p
	// 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
	var s, t [limb4.FieldLimbs]uint64
	params := getK256FpParams()
	limb4.Pow(&s, arg, &[limb4.FieldLimbs]uint64{
		0xffffffffbfffff0c,
		0xffffffffffffffff,
		0xffffffffffffffff,
		0x3fffffffffffffff,
	}, params, f)
	f.Square(&t, &s)
	tv1 := &limb4.FieldValue{Value: t, Params: params, Arithmetic: f}
	tv2 := &limb4.FieldValue{Value: *arg, Params: params, Arithmetic: f}
	*wasSquare = tv1.Equal(tv2)
	f.Selectznz(out, out, &s, *wasSquare)
}

// Invert performs modular inverse.
func (f Arithmetic) Invert(wasInverted *int, out, arg *[limb4.FieldLimbs]uint64) {
	// The binary representation of (p - 2) has 5 groups of 1s, with lengths in
	// { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each group:
	// [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
	var s, x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223 [limb4.FieldLimbs]uint64

	limb4.Pow2k(&x2, arg, 1, f)
	f.Mul(&x2, &x2, arg)

	limb4.Pow2k(&x3, &x2, 1, f)
	f.Mul(&x3, &x3, arg)

	limb4.Pow2k(&x6, &x3, 3, f)
	f.Mul(&x6, &x6, &x3)

	limb4.Pow2k(&x9, &x6, 3, f)
	f.Mul(&x9, &x9, &x3)

	limb4.Pow2k(&x11, &x9, 2, f)
	f.Mul(&x11, &x11, &x2)

	limb4.Pow2k(&x22, &x11, 11, f)
	f.Mul(&x22, &x22, &x11)

	limb4.Pow2k(&x44, &x22, 22, f)
	f.Mul(&x44, &x44, &x22)

	limb4.Pow2k(&x88, &x44, 44, f)
	f.Mul(&x88, &x88, &x44)

	limb4.Pow2k(&x176, &x88, 88, f)
	f.Mul(&x176, &x176, &x88)

	limb4.Pow2k(&x220, &x176, 44, f)
	f.Mul(&x220, &x220, &x44)

	limb4.Pow2k(&x223, &x220, 3, f)
	f.Mul(&x223, &x223, &x3)

	// Use sliding window over the group
	limb4.Pow2k(&s, &x223, 23, f)
	f.Mul(&s, &s, &x22)
	limb4.Pow2k(&s, &s, 5, f)
	f.Mul(&s, &s, arg)
	limb4.Pow2k(&s, &s, 3, f)
	f.Mul(&s, &s, &x2)
	limb4.Pow2k(&s, &s, 2, f)
	f.Mul(&s, &s, arg)

	tv := &limb4.FieldValue{Value: *arg, Params: getK256FpParams(), Arithmetic: f}

	*wasInverted = tv.IsNonZero()
	f.Selectznz(out, out, &s, *wasInverted)
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
func (Arithmetic) Selectznz(out, arg1, arg2 *[limb4.FieldLimbs]uint64, choice int) {
	Selectznz(out, uint1(choice), arg1, arg2)
}
