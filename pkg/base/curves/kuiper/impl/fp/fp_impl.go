package fp

import (
	"encoding/hex"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"
	"github.com/cronokirby/saferith"
	"sync"
)

const (
	fpModulusHex           = "24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5cda8a6c7be4a7a5fe8fadffd6a2a7e8c30006b9459ffffcd300000001"
	fpBitSize              = 446
	fpDivStepsIterationsFp = ((49 * fpBitSize) + 57) / 17
)

var (
	_ limb7.FieldArithmetic = Arithmetic{}

	fpFieldParamsOnce sync.Once
	fpFieldParams     limb7.FieldParams
)

func NewFp() *limb7.FieldValue {
	return &limb7.FieldValue{
		Value:      [limb7.FieldLimbs]uint64{},
		Params:     getFpParams(),
		Arithmetic: Arithmetic{},
	}
}

func fpParamsInit() {
	modulusBytes, err := hex.DecodeString(fpModulusHex)
	if err != nil {
		// this should never happen, string is known constant at compile time to be correct
		panic(err)
	}
	modulus := saferith.ModulusFromBytes(modulusBytes)

	fpFieldParams = limb7.FieldParams{
		// TODO: implement
		//R:            [limb4.FieldLimbs]uint64{0x00000001000003d1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		//R2:           [limb4.FieldLimbs]uint64{0x000007a2000e90a1, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000},
		//R3:           [limb4.FieldLimbs]uint64{0x002bb1e33795f671, 0x0000000100000b73, 0x0000000000000000, 0x0000000000000000},
		//ModulusLimbs: [limb4.FieldLimbs]uint64{0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
		Modulus: modulus,
	}
}

func getFpParams() *limb7.FieldParams {
	fpFieldParamsOnce.Do(fpParamsInit)
	return &fpFieldParams
}

// Arithmetic is a struct with all the methods needed for working
// in mod p.
type Arithmetic struct{}

// ToMontgomery converts this field to montgomery form.
func (Arithmetic) ToMontgomery(out, arg *[limb7.FieldLimbs]uint64) {
	ToMontgomery((*MontgomeryDomainFieldElement)(out), (*NonMontgomeryDomainFieldElement)(arg))
}

// FromMontgomery converts this field from montgomery form.
func (Arithmetic) FromMontgomery(out, arg *[limb7.FieldLimbs]uint64) {
	FromMontgomery((*NonMontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

func (Arithmetic) SetOne(out *[limb7.FieldLimbs]uint64) {
	SetOne((*MontgomeryDomainFieldElement)(out))
}

// Neg performs modular negation.
func (Arithmetic) Neg(out, arg *[limb7.FieldLimbs]uint64) {
	Opp((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Square performs modular square.
func (Arithmetic) Square(out, arg *[limb7.FieldLimbs]uint64) {
	Square((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg))
}

// Mul performs modular multiplication.
func (Arithmetic) Mul(out, arg1, arg2 *[limb7.FieldLimbs]uint64) {
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Add performs modular addition.
func (Arithmetic) Add(out, arg1, arg2 *[limb7.FieldLimbs]uint64) {
	Add((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sub performs modular subtraction.
func (Arithmetic) Sub(out, arg1, arg2 *[limb7.FieldLimbs]uint64) {
	Sub((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(arg1), (*MontgomeryDomainFieldElement)(arg2))
}

// Sqrt performs modular square root.
func (f Arithmetic) Sqrt(wasSquare *uint64, out, arg *[limb7.FieldLimbs]uint64) {
	// TODO: implement
	//// p is congruent to 3 mod 4 we can compute
	//// sqrt using elem^(p+1)/4 mod p
	//// 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
	//var s, t [limb4.FieldLimbs]uint64
	//params := getFpParams()
	//limb7.Pow(&s, arg, &[limb4.FieldLimbs]uint64{
	//	0xffffffffbfffff0c,
	//	0xffffffffffffffff,
	//	0xffffffffffffffff,
	//	0x3fffffffffffffff,
	//}, params, f)
	//f.Square(&t, &s)
	//tv1 := &limb4.FieldValue{Value: t, Params: params, Arithmetic: f}
	//tv2 := &limb4.FieldValue{Value: *arg, Params: params, Arithmetic: f}
	//*wasSquare = tv1.Equal(tv2)
	//f.Selectznz(out, out, &s, *wasSquare)
}

// Invert performs modular inverse.
func (f Arithmetic) Invert(wasInverted *uint64, out, arg *[limb7.FieldLimbs]uint64) {
	var g [limb7.FieldLimbs + 1]uint64
	var precomp [limb7.FieldLimbs]uint64
	var d uint64 = 1
	var ff [limb7.FieldLimbs + 1]uint64
	var v [limb7.FieldLimbs]uint64
	var r [limb7.FieldLimbs]uint64
	var out1 uint64
	var out2, out3 [limb7.FieldLimbs + 1]uint64
	var out4, out5 [limb7.FieldLimbs]uint64
	var h [limb7.FieldLimbs]uint64

	FromMontgomery((*NonMontgomeryDomainFieldElement)(g[:]), (*MontgomeryDomainFieldElement)(arg))
	DivstepPrecomp(&precomp)
	Msat(&ff)
	SetOne((*MontgomeryDomainFieldElement)(&r))

	for i := 0; i < fpDivStepsIterationsFp; i += 2 {
		Divstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		Divstep(&d, &ff, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}

	Opp((*MontgomeryDomainFieldElement)(&h), (*MontgomeryDomainFieldElement)(&v))
	Selectznz(&v, uint1(ff[7]>>63), &v, &h)
	Mul((*MontgomeryDomainFieldElement)(out), (*MontgomeryDomainFieldElement)(&v), (*MontgomeryDomainFieldElement)(&precomp))

	var inverted uint64
	Nonzero(&inverted, out)
	*wasInverted = (inverted | -inverted) >> 63
}

// FromBytes converts a little endian byte array into a field element.
func (Arithmetic) FromBytes(out *[limb7.FieldLimbs]uint64, arg *[limb7.FieldBytes]byte) {
	FromBytes(out, arg)
}

// ToBytes converts a field element to a little endian byte array.
func (Arithmetic) ToBytes(out *[limb7.FieldBytes]byte, arg *[limb7.FieldLimbs]uint64) {
	ToBytes(out, arg)
}

// Selectznz performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (Arithmetic) Selectznz(out, arg1, arg2 *[limb7.FieldLimbs]uint64, choice uint64) {
	Selectznz(out, uint1(choice), arg1, arg2)
}

func (Arithmetic) IsNotZero(out *uint64, arg *[7]uint64) {
	Nonzero(out, arg)
}
