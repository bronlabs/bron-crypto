package impl

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

// Fp2 is a point in p^2.
type Fp2 struct {
	A, B Fp

	_ ds.Incomparable
}

// Set copies a into fp2.
func (f *Fp2) Set(a *Fp2) *Fp2 {
	f.A.Set(&a.A)
	f.B.Set(&a.B)
	return f
}

// SetZero fp2 = 0.
func (f *Fp2) SetZero() *Fp2 {
	f.A.SetZero()
	f.B.SetZero()
	return f
}

// SetOne fp2 = 1.
func (f *Fp2) SetOne() *Fp2 {
	f.A.SetOne()
	f.B.SetZero()
	return f
}

// SetFp creates an element from a lower field.
func (f *Fp2) SetFp(a *Fp) *Fp2 {
	f.A.Set(a)
	f.B.SetZero()
	return f
}

// Random generates a random field element.
func (f *Fp2) Random(prng io.Reader) (*Fp2, error) {
	a, err := new(Fp).Random(prng)
	if err != nil {
		return nil, err
	}
	b, err := new(Fp).Random(prng)
	if err != nil {
		return nil, err
	}
	f.A = *a
	f.B = *b
	return f, nil
}

// IsZero returns 1 if fp2 == 0, 0 otherwise.
func (f *Fp2) IsZero() uint64 {
	return f.A.IsZero() & f.B.IsZero()
}

// IsOne returns 1 if fp2 == 1, 0 otherwise.
func (f *Fp2) IsOne() uint64 {
	return f.A.IsOne() & f.B.IsZero()
}

// Equal returns 1 if f == rhs, 0 otherwise.
func (f *Fp2) Equal(rhs *Fp2) uint64 {
	return f.A.Equal(&rhs.A) & f.B.Equal(&rhs.B)
}

// LexicographicallyLargest returns 1 if
// this element is strictly lexicographically larger than its negation
// 0 otherwise.
func (f *Fp2) LexicographicallyLargest() uint64 {
	// If this element's B coefficient is lexicographically largest
	// then it is lexicographically largest. Otherwise, in the event
	// the B coefficient is zero and the A coefficient is
	// lexicographically largest, then this element is lexicographically
	// largest.

	return f.B.LexicographicallyLargest() |
		(f.B.IsZero() & f.A.LexicographicallyLargest())
}

// Sgn0 returns the lowest bit value.
func (f *Fp2) Sgn0() uint64 {
	// if A = 0 return B.Sgn0  else A.Sgn0
	a := f.A.IsZero()
	t := f.B.Sgn0() & a
	a = a ^ 1
	t |= f.A.Sgn0() & a
	return t
}

// FrobeniusAutomorphism raises this element to p.
func (f *Fp2) FrobeniusAutomorphism(a *Fp2) *Fp2 {
	// This is always just a conjugation. If you're curious why, here's
	// an article about it: https://alicebob.cryptoland.net/the-frobenius-endomorphism-with-finite-fields/
	return f.Conjugate(a)
}

// Conjugate computes the conjugation of this element.
func (f *Fp2) Conjugate(a *Fp2) *Fp2 {
	f.A.Set(&a.A)
	f.B.Neg(&a.B)
	return f
}

// Square computes the square of this element.
// Complex squaring.
func (f *Fp2) Square(arg *Fp2) *Fp2 {
	v0 := new(Fp).Mul(&arg.A, &arg.B)
	betaV0 := f.mulByQuadraticNonResidue(new(Fp), v0)
	betaA1 := f.mulByQuadraticNonResidue(new(Fp), &arg.B)

	f.A.Mul(new(Fp).Add(&arg.A, &arg.B), new(Fp).Add(&arg.A, betaA1))
	f.A.Sub(&f.A, v0)
	f.A.Sub(&f.A, betaV0)
	f.B.Double(v0)
	return f
}

// Add performs field addition.
func (f *Fp2) Add(arg1, arg2 *Fp2) *Fp2 {
	f.A.Add(&arg1.A, &arg2.A)
	f.B.Add(&arg1.B, &arg2.B)
	return f
}

// Double doubles specified element.
func (f *Fp2) Double(a *Fp2) *Fp2 {
	f.A.Double(&a.A)
	f.B.Double(&a.B)
	return f
}

// Sub performs field subtraction.
func (f *Fp2) Sub(arg1, arg2 *Fp2) *Fp2 {
	f.A.Sub(&arg1.A, &arg2.A)
	f.B.Sub(&arg1.B, &arg2.B)
	return f
}

// Mul computes Karatsuba multiplication.
func (f *Fp2) Mul(a, b *Fp2) *Fp2 {
	v0 := new(Fp).Mul(&a.A, &b.A)
	v1 := new(Fp).Mul(&a.B, &b.B)
	betaV1 := f.mulByQuadraticNonResidue(new(Fp), v1)
	a0PlusA1 := new(Fp).Add(&a.A, &a.B)
	b0PlusB1 := new(Fp).Add(&b.A, &b.B)

	f.A.Add(v0, betaV1)
	f.B.Mul(a0PlusA1, b0PlusB1)
	f.B.Sub(&f.B, v0)
	f.B.Sub(&f.B, v1)
	return f
}

func (f *Fp2) Mul0(arg1 *Fp2, arg2 *Fp) *Fp2 {
	f.A.Mul(&arg1.A, arg2)
	f.B.Mul(&arg1.B, arg2)
	return f
}

// MulBy3b.
func (f *Fp2) MulBy3b(arg *Fp2) *Fp2 {
	a2 := new(Fp).Double(&arg.A)
	a3 := new(Fp).Add(&arg.A, a2)
	a4 := new(Fp).Double(a2)
	a8 := new(Fp).Double(a4)
	a9 := new(Fp).Add(&arg.A, a8)

	b2 := new(Fp).Double(&arg.B)
	b3 := new(Fp).Add(&arg.B, b2)
	b4 := new(Fp).Double(b2)
	b8 := new(Fp).Double(b4)
	b9 := new(Fp).Add(&arg.B, b8)
	b15 := f.mulByQuadraticNonResidue(new(Fp), b3)

	f.A.Add(a9, b15)
	f.B.Add(b9, a3)
	return f
}

// Neg performs field negation.
func (f *Fp2) Neg(a *Fp2) *Fp2 {
	f.A.Neg(&a.A)
	f.B.Neg(&a.B)
	return f
}

// Sqrt performs field square root.
func (f *Fp2) Sqrt(a *Fp2) (el *Fp2, e3 uint64) {
	// TODO: this is constant time but is relatively slow,
	// TODO: find faster algorithm (constant time)

	a0 := &a.A
	a1 := &a.B
	a0a0 := new(Fp).Square(a0)
	a1a1 := new(Fp).Square(a1)
	ba1a1 := f.mulByQuadraticNonResidue(new(Fp), a1a1)
	rr := new(Fp).Sub(a0a0, ba1a1)
	r, c1 := new(Fp).Sqrt(rr)

	r2A := new(Fp).Add(a0, r)
	r2HalfA := new(Fp).Mul(r2A, &FpHalf)
	x0A, c2A := new(Fp).Sqrt(r2HalfA)
	twoX0A := new(Fp).Double(x0A)
	twoX0InvA, c3A := new(Fp).Invert(twoX0A)
	x1A := new(Fp).Mul(a1, twoX0InvA)

	r2B := new(Fp).Sub(a0, r)
	r2HalfB := new(Fp).Mul(r2B, &FpHalf)
	x0B, c2B := new(Fp).Sqrt(r2HalfB)
	twoX0B := new(Fp).Double(x0B)
	twoX0InvB, c3B := new(Fp).Invert(twoX0B)
	x1B := new(Fp).Mul(a1, twoX0InvB)

	f.A.CMove(&f.A, x0A, c1&c2A&c3A)
	f.B.CMove(&f.B, x1A, c1&c2A&c3A)

	f.A.CMove(&f.A, x0B, c1&c2B&c3B)
	f.B.CMove(&f.B, x1B, c1&c2B&c3B)

	return f, (c1 & c2A & c3A) | (c1 & c2B & c3B)
}

// Invert computes the multiplicative inverse of this field
// element, returning the original value of fp2
// in the case that this element is zero.
func (f *Fp2) Invert(arg *Fp2) (el *Fp2, wasInverted uint64) {
	aa := new(Fp).Square(&arg.A)
	bb := new(Fp).Square(&arg.B)
	bb5 := f.mulByQuadraticNonResidue(new(Fp), bb)
	den := new(Fp).Sub(aa, bb5)
	denInv, wasInverted := new(Fp).Invert(den)

	a := new(Fp).Mul(&arg.A, denInv)
	b := new(Fp).Neg(new(Fp).Mul(&arg.B, denInv))

	f.A.CMove(&f.A, a, wasInverted)
	f.B.CMove(&f.B, b, wasInverted)
	return f, wasInverted
}

// CMove performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (f *Fp2) CMove(arg1, arg2 *Fp2, choice uint64) *Fp2 {
	f.A.CMove(&arg1.A, &arg2.A, choice)
	f.B.CMove(&arg1.B, &arg2.B, choice)
	return f
}

// CNeg conditionally negates a if choice == 1.
func (f *Fp2) CNeg(a *Fp2, choice uint64) *Fp2 {
	var t Fp2
	t.Neg(a)
	return f.CMove(f, &t, choice)
}

//nolint:unused // TODO
func (f *Fp2) pow(base *Fp2, exp *[FieldLimbs]uint64) {
	res := (&Fp2{}).SetOne()
	tmp := (&Fp2{}).SetZero()

	for i := len(exp) - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			res.Square(res)
			tmp.Mul(res, base)
			res.CMove(res, tmp, (exp[i]>>j)&1)
		}
	}
	f.Set(res)
}

// for Eris beta = -5.
func (*Fp2) mulByQuadraticNonResidue(out, in *Fp) *Fp {
	var t1, t4 Fp
	t1.Neg(in)     // -k
	t4.Double(&t1) // -2k
	t4.Double(&t4) // -4k

	return out.Add(&t1, &t4) // -5k = (-k + -4k)
}
