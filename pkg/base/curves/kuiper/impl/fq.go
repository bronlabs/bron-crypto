package impl

import (
	"io"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const (
	fqDivSteps = ((49 * FieldBits) + 57) / 17
)

var (
	FqOne          Fq
	FqR2           Fq
	FqR3           Fq
	FqModulus      *saferith.Modulus
	FqModulusLimbs [FieldLimbs]uint64
)

type Fq fiatFqMontgomeryDomainFieldElement

//nolint:gochecknoinits // for backward compatibility
func init() {
	var mod [FieldLimbs + 1]uint64
	var modBytes [FieldBytes]byte

	fiatFqSetOne((*fiatFqMontgomeryDomainFieldElement)(&FqOne))
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(&FqR2), (*fiatFqNonMontgomeryDomainFieldElement)(&FqOne))
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(&FqR3), (*fiatFqNonMontgomeryDomainFieldElement)(&FqR2))

	fiatFqMsat(&mod)
	fiatFqToBytes(&modBytes, (*[FieldLimbs]uint64)(mod[:FieldLimbs]))
	slices.Reverse(modBytes[:])
	FqModulus = saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modBytes[:]).Resize(FieldBits))
	copy(FqModulusLimbs[:], mod[:])
}

// IsZero returns 1 if fq == 0, 0 otherwise.
func (f *Fq) IsZero() uint64 {
	var t uint64

	fiatFqNonzero(&t, (*[FieldLimbs]uint64)(f))
	return ((t | -t) >> 63) ^ 1
}

// IsNonZero returns 1 if fq != 0, 0 otherwise.
func (f *Fq) IsNonZero() uint64 {
	var t uint64

	fiatFqNonzero(&t, (*[FieldLimbs]uint64)(f))
	return (t | -t) >> 63
}

// IsOne returns 1 if fq == 1, 0 otherwise.
func (f *Fq) IsOne() uint64 {
	var t uint64
	var one fiatFqMontgomeryDomainFieldElement

	fiatFqSetOne(&one)
	fiatFqSub(&one, &one, (*fiatFqMontgomeryDomainFieldElement)(f))
	fiatFqNonzero(&t, (*[FieldLimbs]uint64)(&one))
	return ((t | -t) >> 63) ^ 1
}

// Cmp returns -1 if f < rhs
// 0 if f == rhs
// 1 if f > rhs.
func (f *Fq) Cmp(rhs *Fq) int64 {
	var l, r fiatFqNonMontgomeryDomainFieldElement

	fiatFqFromMontgomery(&l, (*fiatFqMontgomeryDomainFieldElement)(f))
	fiatFqFromMontgomery(&r, (*fiatFqMontgomeryDomainFieldElement)(rhs))
	return cmpLimbs((*[FieldLimbs]uint64)(&l), (*[FieldLimbs]uint64)(&r))
}

// Equal returns 1 if fq == rhs, 0 otherwise.
func (f *Fq) Equal(rhs *Fq) uint64 {
	var t uint64
	var zero fiatFqMontgomeryDomainFieldElement

	fiatFqSub(&zero, (*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(rhs))
	fiatFqNonzero(&t, (*[FieldLimbs]uint64)(&zero))
	return ((t | -t) >> 63) ^ 1
}

// LexicographicallyLargest returns 1 if
// this element is strictly lexicographically larger than its negation
// 0 otherwise.
func (f *Fq) LexicographicallyLargest() uint64 {
	fNeg := new(Fq).Neg(f)
	t := uint64(f.Cmp(fNeg)) ^ 1
	return ((t | -t) >> 63) ^ 1
}

// Sgn0 returns the lowest bit value.
func (f *Fq) Sgn0() uint64 {
	var t fiatFqNonMontgomeryDomainFieldElement

	fiatFqFromMontgomery(&t, (*fiatFqMontgomeryDomainFieldElement)(f))
	return t[0] & 1
}

// SetOne fq = r.
func (f *Fq) SetOne() *Fq {
	fiatFqSetOne((*fiatFqMontgomeryDomainFieldElement)(f))
	return f
}

// SetZero fq = 0.
func (f *Fq) SetZero() *Fq {
	*f = Fq{}
	return f
}

// SetUint64 fq = rhs.
func (f *Fq) SetUint64(rhs uint64) *Fq {
	var x = fiatFqNonMontgomeryDomainFieldElement{rhs}

	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(f), &x)
	return f
}

// Random generates a random field element.
func (f *Fq) Random(prng io.Reader) (*Fq, error) {
	var t [WideFieldBytes]byte

	_, err := io.ReadFull(prng, t[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "reader failed")
	}
	return f.SetBytesWide(&t), nil
}

// Neg performs modular negation.
func (f *Fq) Neg(a *Fq) *Fq {
	fiatFqOpp((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(a))
	return f
}

// Square performs modular square.
func (f *Fq) Square(a *Fq) *Fq {
	fiatFqSquare((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(a))
	return f
}

// Double this element.
func (f *Fq) Double(a *Fq) *Fq {
	return f.Add(a, a)
}

// Mul performs modular multiplication.
func (f *Fq) Mul(arg1, arg2 *Fq) *Fq {
	fiatFqMul((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(arg1), (*fiatFqMontgomeryDomainFieldElement)(arg2))
	return f
}

// MulBy3b returns arg * 171 or 3 * b.
func (f *Fq) MulBy3b(arg *Fq) *Fq {
	var a2, a4, a8, a16, a32, a64, a128 Fq
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
func (f *Fq) Add(arg1, arg2 *Fq) *Fq {
	fiatFqAdd((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(arg1), (*fiatFqMontgomeryDomainFieldElement)(arg2))
	return f
}

// Sub performs modular subtraction.
func (f *Fq) Sub(arg1, arg2 *Fq) *Fq {
	fiatFqSub((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(arg1), (*fiatFqMontgomeryDomainFieldElement)(arg2))
	return f
}

// Sqrt performs modular square root.
func (f *Fq) Sqrt(a *Fq) (fRes *Fq, wasSquare uint64) {
	return f.tonelliShanks(a)
}

func (f *Fq) tonelliShanks(elem *Fq) (*Fq, uint64) {
	// c1 := 32
	// c2 := (q - 1) / (2^c1)
	// c3 := (c2 - 1) / 2
	// c4 := 7 // the smallest quadratic non-residue (generator)
	// c5 := c4^c2
	c3 := &Fq{
		0xb002857a0ffffe69,
		0x470bbfeb4e53f42e,
		0x3d45363df253baff,
		0x7a1c9337a21fcd2e,
		0x06bfb8725401e53b,
		0x0000120000987000,
		0x0000000012000000,
	}
	c5 := &Fq{
		0x0b2c442a1b1479ca,
		0x109e1af09c6b3178,
		0x1dd2eb740d5a626b,
		0x590fac8bbe958b29,
		0x03877d722cbe5348,
		0x74a33170f87c9af7,
		0x1cecbb4db9bf77a2,
	}

	z := new(Fq).pow(elem, c3)
	t := new(Fq).Square(z)
	t.Mul(t, elem)

	z.Mul(z, elem)

	b := new(Fq).Set(t)
	c := new(Fq).Set(c5)

	for i := 32; i >= 2; i-- {
		for j := 1; j <= i-2; j++ {
			b.Square(b)
		}
		z.CMove(z, new(Fq).Mul(z, c), b.IsOne()^1)
		c.Square(c)
		t.CMove(t, new(Fq).Mul(t, c), b.IsOne()^1)
		b.Set(t)
	}
	wasSquare := c.Square(z).Equal(elem)
	return f.Set(z), wasSquare
}

// Invert performs modular inverse.
func (f *Fq) Invert(a *Fq) (fRes *Fq, wasInverted uint64) {
	var precomp, h, v, r, out4, out5 [FieldLimbs]uint64
	var ff, g, out2, out3 [FieldLimbs + 1]uint64
	var out1, inverted uint64

	d := uint64(1)
	fiatFqDivstepPrecomp(&precomp)
	fiatFqFromMontgomery((*fiatFqNonMontgomeryDomainFieldElement)(g[:]), (*fiatFqMontgomeryDomainFieldElement)(a))
	fiatFqMsat(&ff)
	fiatFqSetOne((*fiatFqMontgomeryDomainFieldElement)(&r))

	for i := 0; i < fqDivSteps-(fqDivSteps%2); i += 2 {
		fiatFqDivstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		fiatFqDivstep(&d, &ff, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}
	if (fqDivSteps % 2) != 0 { // compile time if - always true
		fiatFqDivstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		v = out4
		ff = out2
	}

	fiatFqOpp((*fiatFqMontgomeryDomainFieldElement)(&h), (*fiatFqMontgomeryDomainFieldElement)(&v))
	fiatFqSelectznz(&v, fiatFqUint1(ff[FieldLimbs]>>63), &v, &h)
	fiatFqMul((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(&v), (*fiatFqMontgomeryDomainFieldElement)(&precomp))
	fiatFqNonzero(&inverted, (*[FieldLimbs]uint64)(f))

	return f, (inverted | -inverted) >> 63
}

// SetBytes converts a little endian byte array into a field element
// return 0 if the bytes are not in the field, 1 if they are.
func (f *Fq) SetBytes(arg *[FieldBytes]byte) (fRes *Fq, mask uint64) {
	var t fiatFqNonMontgomeryDomainFieldElement
	fiatFqFromBytes((*[FieldLimbs]uint64)(&t), arg)
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(f), &t)
	check := uint64(cmpLimbs((*[FieldLimbs]uint64)(&t), &FqModulusLimbs) ^ int64(-1))
	return f, ((check | -check) >> 63) ^ 1
}

func (f *Fq) SetBytesWide(a *[WideFieldBytes]byte) *Fq {
	var d1, d0 [FieldLimbs]uint64

	fiatFqFromBytes(&d0, (*[FieldBytes]uint8)(a[:FieldBytes]))
	fiatFqFromBytes(&d1, (*[FieldBytes]uint8)(a[FieldBytes:]))

	// d0*r2 + d1*r3
	fiatFqMul((*fiatFqMontgomeryDomainFieldElement)(&d0), (*fiatFqMontgomeryDomainFieldElement)(&d0), (*fiatFqMontgomeryDomainFieldElement)(&FqR2))
	fiatFqMul((*fiatFqMontgomeryDomainFieldElement)(&d1), (*fiatFqMontgomeryDomainFieldElement)(&d1), (*fiatFqMontgomeryDomainFieldElement)(&FqR3))
	fiatFqAdd((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqMontgomeryDomainFieldElement)(&d0), (*fiatFqMontgomeryDomainFieldElement)(&d1))
	return f
}

// SetNat initialises an element from saferith.Nat
// The value is reduced by the modulus.
func (f *Fq) SetNat(bi *saferith.Nat) *Fq {
	var buffer [FieldBytes]byte
	t := new(saferith.Nat).SetNat(bi)
	t.Mod(t, FqModulus)
	t.FillBytes(buffer[:])
	slices.Reverse(buffer[:])

	fiatFqFromBytes((*[FieldLimbs]uint64)(f), &buffer)
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqNonMontgomeryDomainFieldElement)(f))
	return f
}

// Set copies arg into fq.
func (f *Fq) Set(arg *Fq) *Fq {
	*f = *arg
	return f
}

// SetLimbs converts an array into a field element
// by converting to montgomery form.
func (f *Fq) SetLimbs(a *[FieldLimbs]uint64) *Fq {
	fiatFqToMontgomery((*fiatFqMontgomeryDomainFieldElement)(f), (*fiatFqNonMontgomeryDomainFieldElement)(a))
	return f
}

// SetRaw converts a raw array into a field element
// Assumes input is already in montgomery form.
func (f *Fq) SetRaw(a *[FieldLimbs]uint64) *Fq {
	*f = *a
	return f
}

// Bytes converts a field element to a little endian byte array.
func (f *Fq) Bytes() [FieldBytes]byte {
	var out fiatFqNonMontgomeryDomainFieldElement
	var bytes [FieldBytes]byte

	fiatFqFromMontgomery(&out, (*fiatFqMontgomeryDomainFieldElement)(f))
	fiatFqToBytes(&bytes, (*[FieldLimbs]uint64)(&out))
	return bytes
}

// Nat converts this element into the saferith.Nat struct.
func (f *Fq) Nat() *saferith.Nat {
	buffer := f.Bytes()
	slices.Reverse(buffer[:])
	return new(saferith.Nat).SetBytes(buffer[:])
}

// Raw converts this element into the a [FieldLimbs]uint64.
func (f *Fq) Raw() [FieldLimbs]uint64 {
	return *f
}

// CMove performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (f *Fq) CMove(arg1, arg2 *Fq, choice uint64) *Fq {
	fiatFqSelectznz((*[FieldLimbs]uint64)(f), fiatFqUint1(choice), (*[FieldLimbs]uint64)(arg1), (*[FieldLimbs]uint64)(arg2))
	return f
}

// CNeg conditionally negates a if choice == 1.
func (f *Fq) CNeg(a *Fq, choice uint64) *Fq {
	var t Fq
	t.Neg(a)
	return f.CMove(f, &t, choice)
}

// Exp raises base^exp.
func (f *Fq) Exp(base, exp *Fq) *Fq {
	var e fiatFqNonMontgomeryDomainFieldElement

	fiatFqFromMontgomery(&e, (*fiatFqMontgomeryDomainFieldElement)(exp))
	return f.pow(base, (*Fq)(&e))
}

func (f *Fq) pow(base, e *Fq) *Fq {
	var tmp, res Fq
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
