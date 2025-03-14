package bls12381impl

import (
	"io"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	fpBits     = 381
	fpDivSteps = ((49 * fpBits) + 57) / 17
)

var (
	FpOne          Fp
	FpR2           Fp
	FpR3           Fp
	FpModulus      *saferith.Modulus
	FpModulusLimbs [FieldLimbs]uint64
)

type Fp fiatFpMontgomeryDomainFieldElement

//nolint:gochecknoinits // for backward compatibility
func init() {
	var mod [FieldLimbs + 1]uint64
	var modBytes [FieldBytes]byte

	fiatFpSetOne((*fiatFpMontgomeryDomainFieldElement)(&FpOne))
	fiatFpToMontgomery((*fiatFpMontgomeryDomainFieldElement)(&FpR2), (*fiatFpNonMontgomeryDomainFieldElement)(&FpOne))
	fiatFpToMontgomery((*fiatFpMontgomeryDomainFieldElement)(&FpR3), (*fiatFpNonMontgomeryDomainFieldElement)(&FpR2))

	fiatFpMsat(&mod)
	fiatFpToBytes(&modBytes, (*[6]uint64)(mod[:FieldLimbs]))
	slices.Reverse(modBytes[:])
	FpModulus = saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modBytes[:]).Resize(fpBits))
	copy(FpModulusLimbs[:], mod[:])
}

// IsZero returns 1 if fp == 0, 0 otherwise.
func (f *Fp) IsZero() uint64 {
	var t uint64

	fiatFpNonzero(&t, (*[FieldLimbs]uint64)(f))
	return ((t | -t) >> 63) ^ 1
}

// IsNonZero returns 1 if fp != 0, 0 otherwise.
func (f *Fp) IsNonZero() uint64 {
	var t uint64

	fiatFpNonzero(&t, (*[FieldLimbs]uint64)(f))
	return (t | -t) >> 63
}

// IsOne returns 1 if fp == 1, 0 otherwise.
func (f *Fp) IsOne() uint64 {
	var t uint64
	var one fiatFpMontgomeryDomainFieldElement

	fiatFpSetOne(&one)
	fiatFpSub(&one, &one, (*fiatFpMontgomeryDomainFieldElement)(f))
	fiatFpNonzero(&t, (*[FieldLimbs]uint64)(&one))
	return ((t | -t) >> 63) ^ 1
}

// Cmp returns -1 if f < rhs
// 0 if f == rhs
// 1 if f > rhs.
func (f *Fp) Cmp(rhs *Fp) int64 {
	var l, r fiatFpNonMontgomeryDomainFieldElement

	fiatFpFromMontgomery(&l, (*fiatFpMontgomeryDomainFieldElement)(f))
	fiatFpFromMontgomery(&r, (*fiatFpMontgomeryDomainFieldElement)(rhs))
	return ct.SliceCmpLE(l[:], r[:])
}

// Equal returns 1 if fp == rhs, 0 otherwise.
func (f *Fp) Equal(rhs *Fp) uint64 {
	var t uint64
	var zero fiatFpMontgomeryDomainFieldElement

	fiatFpSub(&zero, (*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(rhs))
	fiatFpNonzero(&t, (*[FieldLimbs]uint64)(&zero))
	return ((t | -t) >> 63) ^ 1
}

// LexicographicallyLargest returns 1 if
// this element is strictly lexicographically larger than its negation
// 0 otherwise.
func (f *Fp) LexicographicallyLargest() uint64 {
	fNeg := new(Fp).Neg(f)
	t := uint64(f.Cmp(fNeg)) ^ 1
	return ((t | -t) >> 63) ^ 1
}

// Sgn0 returns the lowest bit value.
func (f *Fp) Sgn0() uint64 {
	var t fiatFpNonMontgomeryDomainFieldElement

	fiatFpFromMontgomery(&t, (*fiatFpMontgomeryDomainFieldElement)(f))
	return t[0] & 1
}

// SetOne fp = r.
func (f *Fp) SetOne() *Fp {
	fiatFpSetOne((*fiatFpMontgomeryDomainFieldElement)(f))
	return f
}

// SetZero fp = 0.
func (f *Fp) SetZero() *Fp {
	*f = Fp{}
	return f
}

// SetUint64 fp = rhs.
func (f *Fp) SetUint64(rhs uint64) *Fp {
	var x = fiatFpNonMontgomeryDomainFieldElement{rhs}

	fiatFpToMontgomery((*fiatFpMontgomeryDomainFieldElement)(f), &x)
	return f
}

// Random generates a random field element.
func (f *Fp) Random(prng io.Reader) (*Fp, error) {
	var t [WideFieldBytes]byte

	_, err := io.ReadFull(prng, t[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "reader failed")
	}
	return f.SetBytesWide(&t), nil
}

// Neg performs modular negation.
func (f *Fp) Neg(a *Fp) *Fp {
	fiatFpOpp((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(a))
	return f
}

// Square performs modular square.
func (f *Fp) Square(a *Fp) *Fp {
	fiatFpSquare((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(a))
	return f
}

// Double this element.
func (f *Fp) Double(a *Fp) *Fp {
	return f.Add(a, a)
}

// Mul performs modular multiplication.
func (f *Fp) Mul(arg1, arg2 *Fp) *Fp {
	fiatFpMul((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(arg1), (*fiatFpMontgomeryDomainFieldElement)(arg2))
	return f
}

// MulBy3b returns arg * 12 or 3 * b.
func (f *Fp) MulBy3b(arg *Fp) *Fp {
	var a, t Fp
	a.Double(arg) // 2
	t.Double(&a)  // 4
	a.Double(&t)  // 8
	a.Add(&a, &t) // 12
	return f.Set(&a)
}

// Add performs modular addition.
func (f *Fp) Add(arg1, arg2 *Fp) *Fp {
	fiatFpAdd((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(arg1), (*fiatFpMontgomeryDomainFieldElement)(arg2))
	return f
}

// Sub performs modular subtraction.
func (f *Fp) Sub(arg1, arg2 *Fp) *Fp {
	fiatFpSub((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(arg1), (*fiatFpMontgomeryDomainFieldElement)(arg2))
	return f
}

// Sqrt performs modular square root.
func (f *Fp) Sqrt(a *Fp) (fRes *Fp, wasSquare uint64) {
	// Shank's method, as p = 3 (mod 4). This means
	// exponentiate by (p+1)/4. This only works for elements
	// that are actually quadratic residue,
	// so check the result at the end.
	var c, z Fp
	z.pow(a, &Fp{
		0xee7fbfffffffeaab,
		0x07aaffffac54ffff,
		0xd9cc34a83dac3d89,
		0xd91dd2e13ce144af,
		0x92c6e9ed90d2eb35,
		0x0680447a8e5ff9a6,
	})

	c.Square(&z)
	wasSquare = c.Equal(a)
	f.CMove(f, &z, wasSquare)
	return f, wasSquare
}

// Invert performs modular inverse.
func (f *Fp) Invert(a *Fp) (fRes *Fp, wasInverted uint64) {
	var precomp, h, v, r, out4, out5 [FieldLimbs]uint64
	var ff, g, out2, out3 [FieldLimbs + 1]uint64
	var out1, inverted uint64

	d := uint64(1)
	fiatFpDivstepPrecomp(&precomp)
	fiatFpFromMontgomery((*fiatFpNonMontgomeryDomainFieldElement)(g[:]), (*fiatFpMontgomeryDomainFieldElement)(a))
	fiatFpMsat(&ff)
	fiatFpSetOne((*fiatFpMontgomeryDomainFieldElement)(&r))

	for i := 0; i < fpDivSteps-(fpDivSteps%2); i += 2 {
		fiatFpDivstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		fiatFpDivstep(&d, &ff, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}
	if (fpDivSteps % 2) != 0 { // compile time if - always true
		fiatFpDivstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		v = out4
		ff = out2
	}

	fiatFpOpp((*fiatFpMontgomeryDomainFieldElement)(&h), (*fiatFpMontgomeryDomainFieldElement)(&v))
	fiatFpSelectznz(&v, fiatFpUint1(ff[FieldLimbs]>>63), &v, &h)
	fiatFpMul((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(&v), (*fiatFpMontgomeryDomainFieldElement)(&precomp))
	fiatFpNonzero(&inverted, (*[FieldLimbs]uint64)(f))

	return f, (inverted | -inverted) >> 63
}

// SetBytes converts a little endian byte array into a field element
// return 0 if the bytes are not in the field, 1 if they are.
func (f *Fp) SetBytes(arg *[FieldBytes]byte) (fRes *Fp, mask uint64) {
	var t fiatFpNonMontgomeryDomainFieldElement
	fiatFpFromBytes((*[FieldLimbs]uint64)(&t), arg)
	fiatFpToMontgomery((*fiatFpMontgomeryDomainFieldElement)(f), &t)
	check := uint64(ct.SliceCmpLE(t[:], FpModulusLimbs[:]) ^ int64(-1))
	return f, ((check | -check) >> 63) ^ 1
}

// SetBytesWide takes 96 bytes as input and treats them as a 512-bit number.
// Attributed to https://github.com/zcash/pasta_curves/blob/main/src/fields/Fp.rs#L255
// We reduce an arbitrary 768-bit number by decomposing it into two 384-bit digits
// with the higher bits multiplied by 2^384. Thus, we perform two reductions
//
// 1. the lower bits are multiplied by r^2, as normal
// 2. the upper bits are multiplied by r^2 * 2^384 = r^3
//
// and computing their sum in the field. It remains to see that arbitrary 384-bit
// numbers can be placed into Montgomery form safely using the reduction. The
// reduction works so long as the product is less than r=2^384 multiplied by
// the modulus. This holds because for any `c` smaller than the modulus, we have
// that (2^384 - 1)*c is an acceptable product for the reduction. Therefore, the
// reduction always works so long as `c` is in the field; in this case it is either the
// constant `r2` or `r3`.
func (f *Fp) SetBytesWide(a *[WideFieldBytes]byte) *Fp {
	var d1, d0 [FieldLimbs]uint64

	fiatFpFromBytes(&d0, (*[FieldBytes]uint8)(a[:FieldBytes]))
	fiatFpFromBytes(&d1, (*[FieldBytes]uint8)(a[FieldBytes:]))

	// d0*r2 + d1*r3
	fiatFpMul((*fiatFpMontgomeryDomainFieldElement)(&d0), (*fiatFpMontgomeryDomainFieldElement)(&d0), (*fiatFpMontgomeryDomainFieldElement)(&FpR2))
	fiatFpMul((*fiatFpMontgomeryDomainFieldElement)(&d1), (*fiatFpMontgomeryDomainFieldElement)(&d1), (*fiatFpMontgomeryDomainFieldElement)(&FpR3))
	fiatFpAdd((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpMontgomeryDomainFieldElement)(&d0), (*fiatFpMontgomeryDomainFieldElement)(&d1))
	return f
}

// SetNat initialises an element from saferith.Nat
// The value is reduced by the modulus.
func (f *Fp) SetNat(bi *saferith.Nat) *Fp {
	var buffer [FieldBytes]byte
	t := new(saferith.Nat).SetNat(bi)
	t.Mod(t, FpModulus)
	t.FillBytes(buffer[:])
	slices.Reverse(buffer[:])

	fiatFpFromBytes((*[FieldLimbs]uint64)(f), &buffer)
	fiatFpToMontgomery((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpNonMontgomeryDomainFieldElement)(f))
	return f
}

// Set copies a into fp.
func (f *Fp) Set(a *Fp) *Fp {
	*f = *a
	return f
}

// SetLimbs converts an array into a field element
// by converting to montgomery form.
func (f *Fp) SetLimbs(a *[FieldLimbs]uint64) *Fp {
	fiatFpToMontgomery((*fiatFpMontgomeryDomainFieldElement)(f), (*fiatFpNonMontgomeryDomainFieldElement)(a))
	return f
}

// SetRaw converts a raw array into a field element
// Assumes input is already in montgomery form.
func (f *Fp) SetRaw(a *[FieldLimbs]uint64) *Fp {
	*f = *a
	return f
}

// Bytes converts a field element to a little endian byte array.
func (f *Fp) Bytes() [FieldBytes]byte {
	var out fiatFpNonMontgomeryDomainFieldElement
	var bytes [FieldBytes]byte

	fiatFpFromMontgomery(&out, (*fiatFpMontgomeryDomainFieldElement)(f))
	fiatFpToBytes(&bytes, (*[6]uint64)(&out))
	return bytes
}

// Nat converts this element into the saferith.Nat struct.
func (f *Fp) Nat() *saferith.Nat {
	buffer := f.Bytes()
	slices.Reverse(buffer[:])
	return new(saferith.Nat).SetBytes(buffer[:])
}

// Raw converts this element into the a [FieldLimbs]uint64.
func (f *Fp) Raw() [FieldLimbs]uint64 {
	return *f
}

// CMove performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (f *Fp) CMove(arg1, arg2 *Fp, choice uint64) *Fp {
	fiatFpSelectznz((*[6]uint64)(f), fiatFpUint1(choice), (*[6]uint64)(arg1), (*[6]uint64)(arg2))
	return f
}

// CNeg conditionally negates a if choice == 1.
func (f *Fp) CNeg(a *Fp, choice uint64) *Fp {
	var t Fp
	t.Neg(a)
	return f.CMove(f, &t, choice)
}

// Exp raises base^exp.
func (f *Fp) Exp(base, exp *Fp) *Fp {
	var e fiatFpNonMontgomeryDomainFieldElement

	fiatFpFromMontgomery(&e, (*fiatFpMontgomeryDomainFieldElement)(exp))
	return f.pow(base, (*Fp)(&e))
}

func (f *Fp) pow(base, e *Fp) *Fp {
	var tmp, res Fp
	res.SetOne()

	for i := len(e) - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			res.Square(&res)
			tmp.Mul(&res, base)
			res.CMove(&res, &tmp, (e[i]>>j)&1)
		}
	}

	*f = res
	return f
}
