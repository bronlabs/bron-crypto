package fp

import (
	"encoding/hex"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
)

const (
	k256FieldModulusHex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
)

var (
	k256FpInitonce sync.Once
	k256FpParams   impl.FieldParams
)

func New() *impl.FieldValue {
	return &impl.FieldValue{
		Value:      [impl.FieldLimbs]uint64{},
		Params:     getK256FpParams(),
		Arithmetic: k256FpArithmetic{},
	}
}

func k256FpParamsInit() {
	modulusBytes, err := hex.DecodeString(k256FieldModulusHex)
	if err != nil {
		// this should never happen, string is known constant at compile time to be correct
		panic(err)
	}
	modulus := saferith.ModulusFromBytes(modulusBytes)

	k256FpParams = impl.FieldParams{
		R:            [impl.FieldLimbs]uint64{0x00000001000003d1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		R2:           [impl.FieldLimbs]uint64{0x000007a2000e90a1, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000},
		R3:           [impl.FieldLimbs]uint64{0x002bb1e33795f671, 0x0000000100000b73, 0x0000000000000000, 0x0000000000000000},
		ModulusLimbs: [impl.FieldLimbs]uint64{0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
		Modulus:      modulus,
	}
}

func getK256FpParams() *impl.FieldParams {
	k256FpInitonce.Do(k256FpParamsInit)
	return &k256FpParams
}

// k256FpArithmetic is a struct with all the methods needed for working
// in mod p.
type k256FpArithmetic struct{}

// ToMontgomery converts this field to montgomery form.
func (k256FpArithmetic) ToMontgomery(out, arg *[impl.FieldLimbs]uint64) {
	ToMontgomery((*MontgomeryDomainFieldElement)(out), (*NonMontgomeryDomainFieldElement)(arg))
}

// FromMontgomery converts this field from montgomery form.
func (k256FpArithmetic) FromMontgomery(out, arg *[impl.FieldLimbs]uint64) {
	FromMontgomery((*NonMontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Neg performs modular negation.
func (k256FpArithmetic) Neg(out, arg *[impl.FieldLimbs]uint64) {
	Opp((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Square performs modular square.
func (k256FpArithmetic) Square(out, arg *[impl.FieldLimbs]uint64) {
	Square((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Mul performs modular multiplication.
func (k256FpArithmetic) Mul(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Add performs modular addition.
func (k256FpArithmetic) Add(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Add((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sub performs modular subtraction.
func (k256FpArithmetic) Sub(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Sub((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sqrt performs modular square root.
func (f k256FpArithmetic) Sqrt(wasSquare *int, out, arg *[impl.FieldLimbs]uint64) {
	// p is congruent to 3 mod 4 we can compute
	// sqrt using elem^(p+1)/4 mod p
	// 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
	var s, t [impl.FieldLimbs]uint64
	params := getK256FpParams()
	impl.Pow(&s, arg, &[impl.FieldLimbs]uint64{
		0xffffffffbfffff0c,
		0xffffffffffffffff,
		0xffffffffffffffff,
		0x3fffffffffffffff,
	}, params, f)
	f.Square(&t, &s)
	tv1 := &impl.FieldValue{Value: t, Params: params, Arithmetic: f}
	tv2 := &impl.FieldValue{Value: *arg, Params: params, Arithmetic: f}
	*wasSquare = tv1.Equal(tv2)
	f.Selectznz(out, out, &s, *wasSquare)
}

// Invert performs modular inverse.
func (f k256FpArithmetic) Invert(wasInverted *int, out, arg *[impl.FieldLimbs]uint64) {
	// The binary representation of (p - 2) has 5 groups of 1s, with lengths in
	// { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each group:
	// [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
	var s, x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223 [impl.FieldLimbs]uint64

	impl.Pow2k(&x2, arg, 1, f)
	f.Mul(&x2, &x2, arg)

	impl.Pow2k(&x3, &x2, 1, f)
	f.Mul(&x3, &x3, arg)

	impl.Pow2k(&x6, &x3, 3, f)
	f.Mul(&x6, &x6, &x3)

	impl.Pow2k(&x9, &x6, 3, f)
	f.Mul(&x9, &x9, &x3)

	impl.Pow2k(&x11, &x9, 2, f)
	f.Mul(&x11, &x11, &x2)

	impl.Pow2k(&x22, &x11, 11, f)
	f.Mul(&x22, &x22, &x11)

	impl.Pow2k(&x44, &x22, 22, f)
	f.Mul(&x44, &x44, &x22)

	impl.Pow2k(&x88, &x44, 44, f)
	f.Mul(&x88, &x88, &x44)

	impl.Pow2k(&x176, &x88, 88, f)
	f.Mul(&x176, &x176, &x88)

	impl.Pow2k(&x220, &x176, 44, f)
	f.Mul(&x220, &x220, &x44)

	impl.Pow2k(&x223, &x220, 3, f)
	f.Mul(&x223, &x223, &x3)

	// Use sliding window over the group
	impl.Pow2k(&s, &x223, 23, f)
	f.Mul(&s, &s, &x22)
	impl.Pow2k(&s, &s, 5, f)
	f.Mul(&s, &s, arg)
	impl.Pow2k(&s, &s, 3, f)
	f.Mul(&s, &s, &x2)
	impl.Pow2k(&s, &s, 2, f)
	f.Mul(&s, &s, arg)

	tv := &impl.FieldValue{Value: *arg, Params: getK256FpParams(), Arithmetic: f}

	*wasInverted = tv.IsNonZero()
	f.Selectznz(out, out, &s, *wasInverted)
}

// FromBytes converts a little endian byte array into a field element.
func (k256FpArithmetic) FromBytes(out *[impl.FieldLimbs]uint64, arg *[base.FieldBytes]byte) {
	FromBytes(out, arg)
}

// ToBytes converts a field element to a little endian byte array.
func (k256FpArithmetic) ToBytes(out *[base.FieldBytes]byte, arg *[impl.FieldLimbs]uint64) {
	ToBytes(out, arg)
}

// Selectznz performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (k256FpArithmetic) Selectznz(out, arg1, arg2 *[impl.FieldLimbs]uint64, choice int) {
	Selectznz(out, uint1(choice), arg1, arg2)
}
