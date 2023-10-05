package fp

import (
	"encoding/hex"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
)

const (
	p256FieldModulusHex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
)

var (
	p256FpInitonce sync.Once
	p256FpParams   impl.FieldParams
)

func New() *impl.FieldValue {
	return &impl.FieldValue{
		Value:      [impl.FieldLimbs]uint64{},
		Params:     getP256FpParams(),
		Arithmetic: p256FpArithmetic{},
	}
}

func p256FpParamsInit() {
	modulusBytes, err := hex.DecodeString(p256FieldModulusHex)
	if err != nil {
		// this should never happen, string is known constant at compile time to be correct
		panic(err)
	}
	modulus := saferith.ModulusFromBytes(modulusBytes)

	// See FIPS 186-3, section D.2.3
	p256FpParams = impl.FieldParams{
		R:            [impl.FieldLimbs]uint64{0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe},
		R2:           [impl.FieldLimbs]uint64{0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd},
		R3:           [impl.FieldLimbs]uint64{0xfffffffd0000000a, 0xffffffedfffffff7, 0x00000005fffffffc, 0x0000001800000001},
		ModulusLimbs: [impl.FieldLimbs]uint64{0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001},
		Modulus:      modulus,
	}
}

func getP256FpParams() *impl.FieldParams {
	p256FpInitonce.Do(p256FpParamsInit)
	return &p256FpParams
}

// p256FpArithmetic is a struct with all the methods needed for working
// in mod q.
type p256FpArithmetic struct{}

// ToMontgomery converts this field to montgomery form.
func (p256FpArithmetic) ToMontgomery(out, arg *[impl.FieldLimbs]uint64) {
	ToMontgomery((*MontgomeryDomainFieldElement)(out), (*NonMontgomeryDomainFieldElement)(arg))
}

// FromMontgomery converts this field from montgomery form.
func (p256FpArithmetic) FromMontgomery(out, arg *[impl.FieldLimbs]uint64) {
	FromMontgomery((*NonMontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Neg performs modular negation.
func (p256FpArithmetic) Neg(out, arg *[impl.FieldLimbs]uint64) {
	Opp((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Square performs modular square.
func (p256FpArithmetic) Square(out, arg *[impl.FieldLimbs]uint64) {
	Square((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Mul performs modular multiplication.
func (p256FpArithmetic) Mul(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Add performs modular addition.
func (p256FpArithmetic) Add(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Add((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sub performs modular subtraction.
func (p256FpArithmetic) Sub(out, arg1, arg2 *[impl.FieldLimbs]uint64) {
	Sub((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sqrt performs modular square root.
func (f p256FpArithmetic) Sqrt(wasSquare *int, out, arg *[impl.FieldLimbs]uint64) {
	// Use p = 3 mod 4 by Euler's criterion means
	// arg^((p+1)/4 mod p
	var t, c [impl.FieldLimbs]uint64
	c1 := [impl.FieldLimbs]uint64{
		0x0000_0000_0000_0000,
		0x0000_0000_4000_0000,
		0x4000_0000_0000_0000,
		0x3fff_ffff_c000_0000,
	}
	impl.Pow(&t, arg, &c1, getP256FpParams(), f)
	Square((*MontgomeryDomainFieldElement)(&c), (*MontgomeryDomainFieldElement)(&t))
	*wasSquare = (&impl.FieldValue{Value: c, Params: getP256FpParams(), Arithmetic: f}).Equal(&impl.FieldValue{
		Value: *arg, Params: getP256FpParams(), Arithmetic: f,
	})
	Selectznz(out, uint1(*wasSquare), out, &t)
}

// Invert performs modular inverse.
func (f p256FpArithmetic) Invert(wasInverted *int, out, arg *[impl.FieldLimbs]uint64) {
	// Fermat's Little Theorem
	// a ^ (p - 2) mod p
	//
	// The exponent pattern (from high to low) is:
	//  - 32 bits of value 1
	//  - 31 bits of value 0
	//  - 1 bit of value 1
	//  - 96 bits of value 0
	//  - 94 bits of value 1
	//  - 1 bit of value 0
	//  - 1 bit of value 1
	// To speed up the square-and-multiply algorithm, precompute a^(2^31-1).
	//
	// Courtesy of Thomas Pornin
	//
	var t, r [impl.FieldLimbs]uint64
	copy(t[:], arg[:])

	for i := 0; i < 30; i++ {
		f.Square(&t, &t)
		f.Mul(&t, &t, arg)
	}
	copy(r[:], t[:])
	for i := 224; i >= 0; i-- {
		f.Square(&r, &r)
		switch i {
		case 0:
			fallthrough
		case 2:
			fallthrough
		case 192:
			fallthrough
		case 224:
			f.Mul(&r, &r, arg)
		case 3:
			fallthrough
		case 34:
			fallthrough
		case 65:
			f.Mul(&r, &r, &t)
		}
	}

	*wasInverted = (&impl.FieldValue{
		Value:      *arg,
		Params:     getP256FpParams(),
		Arithmetic: f,
	}).IsNonZero()
	Selectznz(out, uint1(*wasInverted), out, &r)
}

// FromBytes converts a little endian byte array into a field element.
func (p256FpArithmetic) FromBytes(out *[impl.FieldLimbs]uint64, arg *[impl.FieldBytes]byte) {
	FromBytes(out, arg)
}

// ToBytes converts a field element to a little endian byte array.
func (p256FpArithmetic) ToBytes(out *[impl.FieldBytes]byte, arg *[impl.FieldLimbs]uint64) {
	ToBytes(out, arg)
}

// Selectznz performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (p256FpArithmetic) Selectznz(out, arg1, arg2 *[impl.FieldLimbs]uint64, choice int) {
	Selectznz(out, uint1(choice), arg1, arg2)
}
