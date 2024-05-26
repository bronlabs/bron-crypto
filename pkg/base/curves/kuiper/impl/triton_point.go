package impl

import (
	"encoding/hex"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	tritonB                  Fp2
	tritonGenerator          TritonPoint
	tritonCofactorBytesLe, _ = hex.DecodeString("24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5d3a8a6c7be4a7d5fe91447fd6a8a7e928a00867971ffffcd300000001")
)

//nolint:gochecknoinits // TODO
func init() {
	tritonB.A.SetUint64(3)
	tritonB.B.SetOne()

	// TODO: I have no idea what the generator should be so I set some random point from subgroup
	tritonGenerator.X.A.SetLimbs(&[7]uint64{
		0xf3898657202e58cb,
		0x415aa2d315f10c34,
		0xe9a9535fd905fe27,
		0x5f14e69bd73c0ffa,
		0x032200fe251b729e,
		0xd3e29bae4c1fb349,
		0x071f33f6fd98da41,
	})
	tritonGenerator.X.B.SetLimbs(&[7]uint64{
		0xe39a5927b99f7c8e,
		0xa4349f8672b000ae,
		0x3d201c5814d9f3ce,
		0x271d69000be7ad62,
		0x1cae1ed391bd0553,
		0xd2cdd2e211df8abf,
		0x171d1edf89686cdf,
	})
	tritonGenerator.Y.A.SetLimbs(&[7]uint64{
		0xaf406af8ccbbf659,
		0x7da325313ddaf117,
		0x3c8d70098237cdce,
		0x5753ffdd277aca5d,
		0xbd745ea40dbf86f5,
		0xf06ba82e7afa7790,
		0x21f352ef30778246,
	})
	tritonGenerator.Y.B.SetLimbs(&[7]uint64{
		0xa073a3997b9dc230,
		0xfab5dd67f1d4d925,
		0x2bbeab302d9af1a0,
		0xe47f5ef2ffb92b9c,
		0xb27ac168b994aad9,
		0x6544e6e38654bc52,
		0x045d2f7b4aab0576,
	})
	tritonGenerator.Z.SetOne()

	if (tritonGenerator.IsOnCurve() & tritonGenerator.InCorrectSubgroup()) != 1 {
		panic("invalid generator")
	}
}

type TritonPoint struct {
	X, Y, Z Fp2

	_ ds.Incomparable
}

// Identity returns the identity point.
func (p *TritonPoint) Identity() *TritonPoint {
	p.X.SetZero()
	p.Y.SetOne()
	p.Z.SetZero()
	return p
}

// Generator returns the base point.
func (p *TritonPoint) Generator() *TritonPoint {
	p.Set(&tritonGenerator)
	return p
}

// IsIdentity returns true if this point is at infinity.
func (p *TritonPoint) IsIdentity() uint64 {
	return p.Z.IsZero()
}

// IsOnCurve determines if this point represents a valid curve point.
func (p *TritonPoint) IsOnCurve() uint64 {
	// Y^2 Z = X^3 + b Z^3
	var lhs, rhs, t Fp2
	lhs.Square(&p.Y)
	lhs.Mul(&lhs, &p.Z)

	rhs.Square(&p.X)
	rhs.Mul(&rhs, &p.X)
	t.Square(&p.Z)
	t.Mul(&t, &p.Z)
	t.Mul(&t, &tritonB)
	rhs.Add(&rhs, &t)

	return lhs.Equal(&rhs)
}

// InCorrectSubgroup returns 1 if the point is torsion free, 0 otherwise.
func (p *TritonPoint) InCorrectSubgroup() uint64 {
	var order [FieldLimbs + 1]uint64
	var orderBytes [FieldBytes]byte

	fiatFqMsat(&order)
	fiatFqToBytes(&orderBytes, (*[7]uint64)(order[:FieldLimbs]))
	return new(TritonPoint).multiply(p, &orderBytes).IsIdentity()
}

// Add adds this point to another point.
func (p *TritonPoint) Add(arg1, arg2 *TritonPoint) *TritonPoint {
	// Algorithm 7, https://eprint.iacr.org/2015/1060.pdf
	var t0, t1, t2, t3, t4, x3, y3, z3 Fp2

	t0.Mul(&arg1.X, &arg2.X)
	t1.Mul(&arg1.Y, &arg2.Y)
	t2.Mul(&arg1.Z, &arg2.Z)
	t3.Add(&arg1.X, &arg1.Y)
	t4.Add(&arg2.X, &arg2.Y)
	t3.Mul(&t3, &t4)
	t4.Add(&t0, &t1)
	t3.Sub(&t3, &t4)
	t4.Add(&arg1.Y, &arg1.Z)
	x3.Add(&arg2.Y, &arg2.Z)
	t4.Mul(&t4, &x3)
	x3.Add(&t1, &t2)
	t4.Sub(&t4, &x3)
	x3.Add(&arg1.X, &arg1.Z)
	y3.Add(&arg2.X, &arg2.Z)
	x3.Mul(&x3, &y3)
	y3.Add(&t0, &t2)
	y3.Sub(&x3, &y3)
	x3.Double(&t0)
	t0.Add(&t0, &x3)
	t2.MulBy3b(&t2)
	z3.Add(&t1, &t2)
	t1.Sub(&t1, &t2)
	y3.MulBy3b(&y3)
	x3.Mul(&t4, &y3)
	t2.Mul(&t3, &t1)
	x3.Sub(&t2, &x3)
	y3.Mul(&y3, &t0)
	t1.Mul(&t1, &z3)
	y3.Add(&t1, &y3)
	t0.Mul(&t0, &t3)
	z3.Mul(&z3, &t4)
	z3.Add(&z3, &t0)

	p.X.Set(&x3)
	p.Y.Set(&y3)
	p.Z.Set(&z3)
	return p
}

// Sub subtracts the two points.
func (p *TritonPoint) Sub(arg1, arg2 *TritonPoint) *TritonPoint {
	var t TritonPoint
	t.Neg(arg2)
	return p.Add(arg1, &t)
}

// Double this point.
func (p *TritonPoint) Double(a *TritonPoint) (a2 *TritonPoint) {
	// Algorithm 9, https://eprint.iacr.org/2015/1060.pdf
	var t0, t1, t2, x3, y3, z3 Fp2

	t0.Square(&a.Y)
	z3.Double(&t0)
	z3.Double(&z3)
	z3.Double(&z3)
	t1.Mul(&a.Y, &a.Z)
	t2.Square(&a.Z)
	t2.MulBy3b(&t2)
	x3.Mul(&t2, &z3)
	y3.Add(&t0, &t2)
	z3.Mul(&t1, &z3)
	t1.Double(&t2)
	t2.Add(&t2, &t1)
	t0.Sub(&t0, &t2)
	y3.Mul(&t0, &y3)
	y3.Add(&y3, &x3)
	t1.Mul(&a.X, &a.Y)
	x3.Mul(&t0, &t1)
	x3.Double(&x3)

	e := a.IsIdentity()
	p.X.CMove(&x3, t0.SetZero(), e)
	p.Z.CMove(&z3, &t0, e)
	p.Y.CMove(&y3, t0.SetOne(), e)
	return p
}

// Mul multiplies this point by the input scalar.
func (p *TritonPoint) Mul(a *TritonPoint, s *Fq) *TritonPoint {
	bytes := s.Bytes()
	return p.multiply(a, &bytes)
}

func (p *TritonPoint) multiply(a *TritonPoint, bytes *[FieldBytes]byte) *TritonPoint {
	var t TritonPoint
	precomputed := [16]*TritonPoint{}
	precomputed[0] = new(TritonPoint).Identity()
	precomputed[1] = new(TritonPoint).Set(a)
	for i := 2; i < 16; i += 2 {
		precomputed[i] = new(TritonPoint).Double(precomputed[i>>1])
		precomputed[i+1] = new(TritonPoint).Add(precomputed[i], a)
	}
	t.Identity()
	for i := 0; i < (8 * FieldBytes); i += 4 {
		// Brouwer / windowing method. window size of 4.
		for j := 0; j < 4; j++ {
			t.Double(&t)
		}
		window := bytes[FieldBytes-1-i>>3] >> (4 - i&0x04) & 0x0F
		t.Add(&t, precomputed[window])
	}
	return p.Set(&t)
}

// MulByU multiplies by BN u using double and add.
func (p *TritonPoint) MulByU(a *TritonPoint) *TritonPoint {
	// Skip first bit since its always zero
	var s, t, r TritonPoint
	r.Identity()
	t.Set(a)

	for x := paramBNLo >> 1; x != 0; x >>= 1 {
		t.Double(&t)
		s.Add(&r, &t)
		r.CMove(&r, &s, x&1)
	}
	for x := paramBNHi; x != 0; x >>= 1 {
		t.Double(&t)
		s.Add(&r, &t)
		r.CMove(&r, &s, x&1)
	}
	// Since U is negative, flip the sign
	return p.Neg(&r)
}

func (p *TritonPoint) ClearCofactor(a *TritonPoint) *TritonPoint {
	p.multiply(a, (*[FieldBytes]byte)(tritonCofactorBytesLe[:]))
	return p
}

// Neg negates this point.
func (p *TritonPoint) Neg(a *TritonPoint) *TritonPoint {
	p.Set(a)
	p.Y.CNeg(&a.Y, a.IsIdentity()^1)
	return p
}

// Set copies a into p.
func (p *TritonPoint) Set(a *TritonPoint) *TritonPoint {
	p.X.Set(&a.X)
	p.Y.Set(&a.Y)
	p.Z.Set(&a.Z)
	return p
}

// ToCompressed serialises this element into compressed form.
func (p *TritonPoint) ToCompressed() [2 * FieldBytes]byte {
	var out [FieldBytesFp2]byte
	var t TritonPoint
	t.ToAffine(p)
	xABytes := t.X.A.Bytes()
	xBBytes := t.X.B.Bytes()
	copy(out[:FieldBytes], bitstring.ReverseBytes(xBBytes[:]))
	copy(out[FieldBytes:], bitstring.ReverseBytes(xABytes[:]))

	isInfinity := byte(p.IsIdentity())

	// Is infinity
	out[0] |= (1 << 7) & -isInfinity
	// Sign of y only set if not infinity
	out[0] |= (byte(t.Y.LexicographicallyLargest()) << 6) & (isInfinity - 1)
	return out
}

// FromCompressed deserializes this element from compressed form.
func (p *TritonPoint) FromCompressed(input *[2 * FieldBytes]byte) (*TritonPoint, error) {
	var xFp, yFp Fp2
	var xA, xB [FieldBytes]byte
	var t TritonPoint

	infinityFlag := uint64((input[0] >> 7) & 1)
	sortFlag := uint64((input[0] >> 6) & 1)

	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		return t.Identity(), nil
	}

	copy(xB[:], bitstring.ReverseBytes(input[:FieldBytes]))
	copy(xA[:], bitstring.ReverseBytes(input[FieldBytes:]))
	// Mask away the flag bits
	xB[FieldBytes-1] &= 0x3F
	_, validA := xFp.A.SetBytes(&xA)
	_, validB := xFp.B.SetBytes(&xB)

	if validA&validB != 1 {
		return nil, errs.NewFailed("invalid bytes - not in field")
	}

	// Recover a y-coordinate given x by y = sqrt(x^3 + 4)
	yFp.Square(&xFp)
	yFp.Mul(&yFp, &xFp)
	yFp.Add(&yFp, &tritonB)

	if _, wasSquare := yFp.Sqrt(&yFp); wasSquare != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}

	yFp.CNeg(&yFp, yFp.LexicographicallyLargest()^sortFlag)
	t.X.Set(&xFp)
	t.Y.Set(&yFp)
	t.Z.SetOne()
	if t.InCorrectSubgroup() == 0 {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return p.Set(&t), nil
}

// ToUncompressed serialises this element into uncompressed form.
func (*TritonPoint) ToUncompressed() [2 * WideFieldBytes]byte {
	panic("not implemented")
	//var out [WideFieldBytes]byte
	//var t G1
	//t.ToAffine(g1)
	//xBytes := t.X.Bytes()
	//yBytes := t.Y.Bytes()
	//copy(out[:FieldBytes], bitstring.ReverseBytes(xBytes[:]))
	//copy(out[FieldBytes:], bitstring.ReverseBytes(yBytes[:]))
	//isInfinity := byte(g1.IsIdentity())
	//out[0] |= (1 << 6) & -isInfinity
	//return out
}

// FromUncompressed deserializes this element from uncompressed form.
func (*TritonPoint) FromUncompressed(input *[2 * WideFieldBytes]byte) (*TritonPoint, error) {
	panic("not implemented")
}

// ToAffine converts the point into affine coordinates.
func (p *TritonPoint) ToAffine(a *TritonPoint) *TritonPoint {
	var wasInverted uint64
	var zero, x, y, z Fp2
	_, wasInverted = z.Invert(&a.Z)
	x.Mul(&a.X, &z)
	y.Mul(&a.Y, &z)

	p.X.CMove(&zero, &x, wasInverted)
	p.Y.CMove(&zero, &y, wasInverted)
	p.Z.CMove(&zero, z.SetOne(), wasInverted)
	return p
}

// GetX returns the affine X coordinate.
func (p *TritonPoint) GetX() *Fp2 {
	var x, zInv Fp2
	zInv.Invert(&p.Z)
	x.Mul(&p.X, &zInv)
	return &x
}

// GetY returns the affine Y coordinate.
func (p *TritonPoint) GetY() *Fp2 {
	var y, zInv Fp2
	zInv.Invert(&p.Z)
	y.Mul(&p.Y, &zInv)
	return &y
}

// Equal returns 1 if the two points are equal 0 otherwise.
func (p *TritonPoint) Equal(rhs *TritonPoint) uint64 {
	var x1, x2, y1, y2 Fp2
	var e1, e2 uint64

	// This technique avoids inversions
	x1.Mul(&p.X, &rhs.Z)
	x2.Mul(&rhs.X, &p.Z)

	y1.Mul(&p.Y, &rhs.Z)
	y2.Mul(&rhs.Y, &p.Z)

	e1 = p.Z.IsZero()
	e2 = p.Z.IsZero()

	// Both at infinity or coordinates are the same
	return (e1 & e2) | ((e1 ^ 1) & (e2 ^ 1) & x1.Equal(&x2) & y1.Equal(&y2))
}

// CMove sets p = arg1 if choice == 0 and p = arg2 if choice == 1.
func (p *TritonPoint) CMove(arg1, arg2 *TritonPoint, choice uint64) *TritonPoint {
	p.X.CMove(&arg1.X, &arg2.X, choice)
	p.Y.CMove(&arg1.Y, &arg2.Y, choice)
	p.Z.CMove(&arg1.Z, &arg2.Z, choice)
	return p
}
