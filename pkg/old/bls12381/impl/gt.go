package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
)

// GtBytes is the number of bytes needed to represent this field.
const GtBytes = 12 * FpBytes

//var _ pointsImpl.Point[*Gt, *Fp6] = (*Gt)(nil).

// Gt is the target group.
type Gt struct {
	Fp12
}

// Bytes returns the Gt field byte representation.
func (gt *Gt) Bytes() []byte {
	var out [GtBytes]byte
	t := gt.U0.U0.U0.Bytes()
	copy(out[:FpBytes], bitstring.ReverseBytes(t))
	t = gt.U0.U0.U1.Bytes()
	copy(out[FpBytes:2*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U0.U1.U0.Bytes()
	copy(out[2*FpBytes:3*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U0.U1.U1.Bytes()
	copy(out[3*FpBytes:4*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U0.U2.U0.Bytes()
	copy(out[4*FpBytes:5*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U0.U2.U1.Bytes()
	copy(out[5*FpBytes:6*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U1.U0.U0.Bytes()
	copy(out[6*FpBytes:7*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U1.U0.U1.Bytes()
	copy(out[7*FpBytes:8*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U1.U1.U0.Bytes()
	copy(out[8*FpBytes:9*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U1.U1.U1.Bytes()
	copy(out[9*FpBytes:10*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U1.U2.U0.Bytes()
	copy(out[10*FpBytes:11*FpBytes], bitstring.ReverseBytes(t))
	t = gt.U1.U2.U1.Bytes()
	copy(out[11*FpBytes:], bitstring.ReverseBytes(t))

	return out[:]
}

// SetBytes attempts to convert a big-endian byte representation of
// a scalar into a `Gt`, failing if the input is not canonical.
func (gt *Gt) SetBytes(input []byte) (ok uint64) {
	var t [FpBytes]byte
	var valid [12]uint64
	copy(t[:], bitstring.ReverseBytes(input[:FpBytes]))
	valid[0] = gt.U0.U0.U0.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[FpBytes:2*FpBytes]))
	valid[1] = gt.U0.U0.U1.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[2*FpBytes:3*FpBytes]))
	valid[2] = gt.U0.U1.U0.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[3*FpBytes:4*FpBytes]))
	valid[3] = gt.U0.U1.U1.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[4*FpBytes:5*FpBytes]))
	valid[4] = gt.U0.U2.U0.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[5*FpBytes:6*FpBytes]))
	valid[5] = gt.U0.U2.U1.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[6*FpBytes:7*FpBytes]))
	valid[6] = gt.U1.U0.U0.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[7*FpBytes:8*FpBytes]))
	valid[7] = gt.U1.U0.U1.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[8*FpBytes:9*FpBytes]))
	valid[8] = gt.U1.U1.U0.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[9*FpBytes:10*FpBytes]))
	valid[9] = gt.U1.U1.U1.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[10*FpBytes:11*FpBytes]))
	valid[10] = gt.U1.U2.U0.SetBytes(t[:])
	copy(t[:], bitstring.ReverseBytes(input[11*FpBytes:12*FpBytes]))
	valid[11] = gt.U1.U2.U1.SetBytes(t[:])

	return valid[0] & valid[1] &
		valid[2] & valid[3] &
		valid[4] & valid[5] &
		valid[6] & valid[7] &
		valid[8] & valid[9] &
		valid[10] & valid[11]
}

// FinalExponentiation performs a "final exponentiation" routine to convert the result
// of a Miller loop into an element of `Gt` with help of efficient squaring
// operation in the so-called `cyclotomic subgroup` of `Fq6` so that
// it can be compared with other elements of `Gt`.
func (gt *Gt) FinalExponentiation(a *Gt) {
	var t0, t1, t2, t3, t4, t5, t6, t Fp12
	Fp12FrobeniusAutomorphism(&t0, &a.Fp12)
	Fp12FrobeniusAutomorphism(&t0, &t0)
	Fp12FrobeniusAutomorphism(&t0, &t0)
	Fp12FrobeniusAutomorphism(&t0, &t0)
	Fp12FrobeniusAutomorphism(&t0, &t0)
	Fp12FrobeniusAutomorphism(&t0, &t0)

	// Shouldn't happen since we enforce `a` to be non-zero but just in case
	wasInverted := t1.Inv(&a.Fp12)
	t2.Mul(&t0, &t1)
	t1.Set(&t2)
	Fp12FrobeniusAutomorphism(&t2, &t2)
	Fp12FrobeniusAutomorphism(&t2, &t2)
	t2.Mul(&t2, &t1)
	CyclotomicSquare(&t1, &t2)
	Conjugate(&t1, &t1)

	CyclotomicExp(&t3, &t2, X)
	CyclotomicSquare(&t4, &t3)
	t5.Mul(&t1, &t3)
	CyclotomicExp(&t1, &t5, X)
	CyclotomicExp(&t0, &t1, X)
	CyclotomicExp(&t6, &t0, X)
	t6.Mul(&t6, &t4)
	CyclotomicExp(&t4, &t6, X)
	Conjugate(&t5, &t5)
	t4.Mul(&t4, &t5)
	t4.Mul(&t4, &t2)
	Conjugate(&t5, &t2)
	t1.Mul(&t1, &t2)
	Fp12FrobeniusAutomorphism(&t1, &t1)
	Fp12FrobeniusAutomorphism(&t1, &t1)
	Fp12FrobeniusAutomorphism(&t1, &t1)
	t6.Mul(&t6, &t5)
	Fp12FrobeniusAutomorphism(&t6, &t6)
	t3.Mul(&t3, &t0)
	Fp12FrobeniusAutomorphism(&t3, &t3)
	Fp12FrobeniusAutomorphism(&t3, &t3)
	t3.Mul(&t3, &t1)
	t3.Mul(&t3, &t6)
	t.Mul(&t3, &t4)

	gt.Select(wasInverted, &gt.Fp12, &t)
}

func Fp12FrobeniusAutomorphism(f, arg *Fp12) *Fp12 {
	var a, b, up1epm1div6 Fp6

	// (u + 1)^((p - 1) / 6)
	up1epm1div6.U0 = Fp2{
		U0: Fp{
			fiatFpMontgomeryDomainFieldElement: fiatFpMontgomeryDomainFieldElement{
				0x07089552b319d465,
				0xc6695f92b50a8313,
				0x97e83cccd117228f,
				0xa35baecab2dc29ee,
				0x1ce393ea5daace4d,
				0x08f2220fb0fb66eb,
			},
		},
		U1: Fp{
			fiatFpMontgomeryDomainFieldElement: fiatFpMontgomeryDomainFieldElement{
				0xb2f66aad4ce5d646,
				0x5842a06bfc497cec,
				0xcf4895d42599d394,
				0xc11b9cba40a8e8d0,
				0x2e3813cbe5a0de89,
				0x110eefda88847faf,
			},
		},
	}

	Fp6FrobeniusAutomorphism(&a, &arg.U0)
	Fp6FrobeniusAutomorphism(&b, &arg.U1)

	// b' = b' * (u + 1)^((p - 1) / 6)
	b.Mul(&b, &up1epm1div6)

	f.U0.Set(&a)
	f.U1.Set(&b)
	return f
}

// Fp6FrobeniusAutomorphism raises this element to p.
func Fp6FrobeniusAutomorphism(f, arg *Fp6) *Fp6 {
	var a, b, c Fp2
	pm1Div3 := Fp2{
		U1: Fp{
			fiatFpMontgomeryDomainFieldElement: fiatFpMontgomeryDomainFieldElement{
				0xcd03c9e48671f071,
				0x5dab22461fcda5d2,
				0x587042afd3851b95,
				0x8eb60ebe01bacb9e,
				0x03f97d6e83d050d2,
				0x18f0206554638741,
			},
		},
	}
	p2m2Div3 := Fp2{
		U0: Fp{
			fiatFpMontgomeryDomainFieldElement: fiatFpMontgomeryDomainFieldElement{
				0x890dc9e4867545c3,
				0x2af322533285a5d5,
				0x50880866309b7e2c,
				0xa20d1b8c7e881024,
				0x14e4f04fe2db9068,
				0x14e56d3f1564853a,
			},
		},
	}
	Fp2FrobeniusAutomorphism(&a, &arg.U0)
	Fp2FrobeniusAutomorphism(&b, &arg.U1)
	Fp2FrobeniusAutomorphism(&c, &arg.U2)

	// b = b * (u + 1)^((p - 1) / 3)
	b.Mul(&b, &pm1Div3)

	// c = c * (u + 1)^((2p - 2) / 3)
	c.Mul(&c, &p2m2Div3)

	f.U0.Set(&a)
	f.U1.Set(&b)
	f.U2.Set(&c)
	return f
}

// Fp2FrobeniusAutomorphism raises this element to p.
func Fp2FrobeniusAutomorphism(f, a *Fp2) {
	// This is always just a conjugation. If you're curious why, here's
	// an article about it: https://alicebob.cryptoland.net/the-frobenius-endomorphism-with-finite-fields/
	Conjugate(f, a)
}

func CyclotomicExp(f *Fp12, a *Fp12, exp uint64) {
	var t Fp12
	t.SetOne()
	foundOne := uint64(0)

	for i := 63; i >= 0; i-- {
		b := (exp >> i) & 1
		if foundOne == 1 {
			CyclotomicSquare(&t, &t)
		} else {
			foundOne = b
		}
		if b == 1 {
			t.Mul(&t, a)
		}
	}
	Conjugate(f, &t)
}

func CyclotomicSquare(f, a *Fp12) {
	// Adaptation of Algorithm 5.5.4, Guide to Pairing-Based Cryptography
	// Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions
	// https://eprint.iacr.org/2009/565.pdf
	var params fp6Params
	var z0, z1, z2, z3, z4, z5, t0, t1, t2, t3 Fp2
	z0.Set(&a.U0.U0)
	z4.Set(&a.U0.U1)
	z3.Set(&a.U0.U2)
	z2.Set(&a.U1.U0)
	z1.Set(&a.U1.U1)
	z5.Set(&a.U1.U2)

	fp4Square(&t0, &t1, &z0, &z1)
	z0.Sub(&t0, &z0)
	z0.Add(&z0, &z0)
	z0.Add(&z0, &t0)

	z1.Add(&t1, &z1)
	z1.Add(&z1, &z1)
	z1.Add(&z1, &t1)

	fp4Square(&t0, &t1, &z2, &z3)
	fp4Square(&t2, &t3, &z4, &z5)

	z4.Sub(&t0, &z4)
	z4.Add(&z4, &z4)
	z4.Add(&z4, &t0)

	z5.Add(&z5, &t1)
	z5.Add(&z5, &z5)
	z5.Add(&z5, &t1)

	params.MulByCubicNonResidue(&t0, &t3)
	z2.Add(&z2, &t0)
	z2.Add(&z2, &z2)
	z2.Add(&z2, &t0)

	z3.Sub(&t2, &z3)
	z3.Add(&z3, &z3)
	z3.Add(&z3, &t2)

	f.U0.U0.Set(&z0)
	f.U0.U1.Set(&z4)
	f.U0.U2.Set(&z3)
	f.U1.U0.Set(&z2)
	f.U1.U1.Set(&z1)
	f.U1.U2.Set(&z5)
}

func Conjugate[BFP fieldsImpl.FiniteFieldPtrConstraint[BFP, BF], A fieldsImpl.QuadraticFieldExtensionArith[BFP], BF any](f, arg *fieldsImpl.QuadraticFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Set(&arg.U0)
	BFP(&f.U1).Neg(&arg.U1)
}

func fp4Square(a, b, arg1, arg2 *Fp2) {
	var params fp6Params
	var t0, t1, t2 Fp2

	t0.Square(arg1)
	t1.Square(arg2)
	params.MulByCubicNonResidue(&t2, &t1)
	a.Add(&t2, &t0)
	t2.Add(arg1, arg2)
	t2.Square(&t2)
	t2.Sub(&t2, &t0)
	b.Sub(&t2, &t1)
}
