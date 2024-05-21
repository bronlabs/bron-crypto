package impl

import (
	"io"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const (
	fpDivSteps = ((49 * FieldBits) + 57) / 17
)

var (
	FpHalf         Fp
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

	two := new(Fp).Add(&FpOne, &FpOne)
	_, check := FpHalf.Invert(two)
	if check != 1 {
		panic("cannot compute 1/2")
	}

	fiatFpMsat(&mod)
	fiatFpToBytes(&modBytes, (*[FieldLimbs]uint64)(mod[:FieldLimbs]))
	slices.Reverse(modBytes[:])
	FpModulus = saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modBytes[:]).Resize(FieldBits))
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
	return cmpLimbs((*[FieldLimbs]uint64)(&l), (*[FieldLimbs]uint64)(&r))
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

// MulBy3b returns arg * 171 or arg * 3b (b = 57).
func (f *Fp) MulBy3b(arg *Fp) *Fp {
	var a2, a4, a8, a16, a32, a64, a128 Fp
	a2.Double(arg)
	a4.Double(&a2)
	a8.Double(&a4)
	a16.Double(&a8)
	a32.Double(&a16)
	a64.Double(&a32)
	a128.Double(&a64)

	f.Set(arg)      // 1
	f.Add(f, &a2)   // 1 + 2
	f.Add(f, &a8)   // 1 + 2 + 8
	f.Add(f, &a32)  // 1 + 2 + 8 + 32
	f.Add(f, &a128) // 1 + 2 + 8 + 32 + 128 == 171
	return f
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
	return f.tonelliShanks(a)
}

func (f *Fp) tonelliShanks(elem *Fp) (*Fp, uint64) {
	// c1 := 32
	// c2 := (p - 1) / (2^c1)
	// c3 := (c2 - 1) / 2
	// c4 := 5 // the smallest quadratic non-residue (generator)
	// c5 := c4^c2
	c3 := &Fp{
		0x80035ca2cffffe69,
		0x47d6ffeb5153f461,
		0x6d45363df253d2ff,
		0x7a1c9337a21fcd2e,
		0x06bfb8725401e53b,
		0x0000120000987000,
		0x0000000012000000,
	}
	c5 := &Fp{
		0xd494a85b13b9cb2f,
		0xf8cccc1f17a30dcc,
		0x36c12d224712e63c,
		0x8dab5683cc38ff9e,
		0xd142523e4680a87c,
		0xceee5878d9c58905,
		0x1a66a0386be6a836,
	}

	z := new(Fp).pow(elem, c3)
	t := new(Fp).Square(z)
	t.Mul(t, elem)

	z.Mul(z, elem)

	b := new(Fp).Set(t)
	c := new(Fp).Set(c5)

	for i := 32; i >= 2; i-- {
		for j := 1; j <= i-2; j++ {
			b.Square(b)
		}
		z.CMove(z, new(Fp).Mul(z, c), b.IsOne()^1)
		c.Square(c)
		t.CMove(t, new(Fp).Mul(t, c), b.IsOne()^1)
		b.Set(t)
	}
	wasSquare := c.Square(z).Equal(elem)
	return f.Set(z), wasSquare
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
	check := uint64(cmpLimbs((*[FieldLimbs]uint64)(&t), &FpModulusLimbs) ^ int64(-1))
	return f, ((check | -check) >> 63) ^ 1
}

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

// Set copies arg into fp.
func (f *Fp) Set(arg *Fp) *Fp {
	*f = *arg
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
	fiatFpToBytes(&bytes, (*[FieldLimbs]uint64)(&out))
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
	fiatFpSelectznz((*[FieldLimbs]uint64)(f), fiatFpUint1(choice), (*[FieldLimbs]uint64)(arg1), (*[FieldLimbs]uint64)(arg2))
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

func cmpLimbs(l, r *[FieldLimbs]uint64) int64 {
	gt := uint64(0)
	lt := uint64(0)
	for i := FieldLimbs - 1; i >= 0; i-- {
		// convert to two 64-bit numbers where
		// the leading bits are zeros and hold no meaning
		//  so rhs - f actually means gt
		// and f - rhs actually means lt.
		rhsH := r[i] >> 32
		rhsL := r[i] & 0xffffffff
		lhsH := l[i] >> 32
		lhsL := l[i] & 0xffffffff

		// Check the leading bit
		// if negative then f > rhs
		// if positive then f < rhs
		gt |= (rhsH - lhsH) >> 32 & 1 &^ lt
		lt |= (lhsH - rhsH) >> 32 & 1 &^ gt
		gt |= (rhsL - lhsL) >> 32 & 1 &^ lt
		lt |= (lhsL - rhsL) >> 32 & 1 &^ gt
	}

	// Make the result -1 for <, 0 for =, 1 for >
	return int64(gt) - int64(lt)
}
