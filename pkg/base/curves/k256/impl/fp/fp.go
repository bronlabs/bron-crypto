package fp

import (
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
)

const (
	k256FieldBits     = 256
	k256FieldBytes    = limb4.FieldBytes
	k256SatFieldLimbs = limb4.FieldLimbs + 1
	k256DivSteps      = ((49 * k256FieldBits) + 57) / 17
)

var (
	k256FpInitOnce sync.Once
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
	var r, r2, r3 [limb4.FieldLimbs]uint64
	var mod [k256SatFieldLimbs]uint64
	var modBytes [k256FieldBytes]byte

	SetOne((*MontgomeryDomainFieldElement)(&r))
	ToMontgomery((*MontgomeryDomainFieldElement)(&r2), (*NonMontgomeryDomainFieldElement)(&r))
	ToMontgomery((*MontgomeryDomainFieldElement)(&r3), (*NonMontgomeryDomainFieldElement)(&r2))
	Msat((*[5]uint64)(mod[:]))
	ToBytes(&modBytes, (*[4]uint64)(mod[:limb4.FieldLimbs]))
	slices.Reverse(modBytes[:])
	modulus := saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modBytes[:]))

	k256FpParams = limb4.FieldParams{
		R:            r,
		R2:           r2,
		R3:           r3,
		ModulusLimbs: [4]uint64(mod[:limb4.FieldLimbs]),
		Modulus:      modulus,
	}
}

func getK256FpParams() *limb4.FieldParams {
	k256FpInitOnce.Do(k256FpParamsInit)
	return &k256FpParams
}

// Arithmetic is a struct with all the methods needed for working
// in mod p.
type Arithmetic struct{}

var _ limb4.FieldArithmetic = Arithmetic{}

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
func (Arithmetic) Invert(wasInverted *uint64, out, arg *[limb4.FieldLimbs]uint64) {
	var precomp [limb4.FieldLimbs]uint64
	DivstepPrecomp(&precomp)

	d := uint64(1)
	var f, g [k256SatFieldLimbs]uint64
	var v, r, out4, out5 [limb4.FieldLimbs]uint64
	var out1 uint64
	var out2, out3 [k256SatFieldLimbs]uint64

	FromMontgomery((*NonMontgomeryDomainFieldElement)(g[:]), (*MontgomeryDomainFieldElement)(arg))
	Msat(&f)
	SetOne((*MontgomeryDomainFieldElement)(&r))

	for i := 0; i < k256DivSteps-(k256DivSteps%2); i += 2 {
		Divstep(&out1, &out2, &out3, &out4, &out5, d, &f, &g, &v, &r)
		Divstep(&d, &f, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}
	if (k256DivSteps % 2) != 0 { // compile time if - always true
		Divstep(&out1, &out2, &out3, &out4, &out5, d, &f, &g, &v, &r)
		v = out4
		f = out2
	}

	var h [limb4.FieldLimbs]uint64
	Opp((*MontgomeryDomainFieldElement)(&h), (*MontgomeryDomainFieldElement)(&v))
	Selectznz(&v, uint1(f[k256SatFieldLimbs-1]>>63), &v, &h)
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
	wasNonZero := uint64(0)
	Nonzero(&wasNonZero, arg)
	*out = (wasNonZero | -wasNonZero) >> 63
}

func (Arithmetic) SetOne(out *[limb4.FieldLimbs]uint64) {
	SetOne((*MontgomeryDomainFieldElement)(out))
}
