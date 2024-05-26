package impl

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	erisB         Fq
	erisGenerator ErisPoint
)

//nolint:gochecknoinits // TODO
func init() {
	erisB.SetUint64(57)

	erisGenerator.X.Neg(new(Fq).SetUint64(2))
	erisGenerator.Y.SetUint64(7)
	erisGenerator.Z.SetOne()
}

type ErisPoint struct {
	X, Y, Z Fq

	_ ds.Incomparable
}

// Identity returns the identity point.
func (p *ErisPoint) Identity() *ErisPoint {
	p.X.SetZero()
	p.Y.SetOne()
	p.Z.SetZero()
	return p
}

// Generator returns the base point.
func (p *ErisPoint) Generator() *ErisPoint {
	p.Set(&erisGenerator)
	return p
}

// IsIdentity returns true if this point is at infinity.
func (p *ErisPoint) IsIdentity() uint64 {
	return p.Z.IsZero()
}

// IsOnCurve determines if this point represents a valid curve point.
func (p *ErisPoint) IsOnCurve() uint64 {
	// Y^2 Z = X^3 + b Z^3
	var lhs, rhs, t Fq
	lhs.Square(&p.Y)
	lhs.Mul(&lhs, &p.Z)

	rhs.Square(&p.X)
	rhs.Mul(&rhs, &p.X)
	t.Square(&p.Z)
	t.Mul(&t, &p.Z)
	t.Mul(&t, &erisB)
	rhs.Add(&rhs, &t)

	return lhs.Equal(&rhs)
}

// InCorrectSubgroup returns 1 if the point is torsion free, 0 otherwise.
func (*ErisPoint) InCorrectSubgroup() uint64 {
	return 1
}

// Add adds this point to another point.
func (p *ErisPoint) Add(arg1, arg2 *ErisPoint) *ErisPoint {
	// Algorithm 7, https://eprint.iacr.org/2015/1060.pdf
	var t0, t1, t2, t3, t4, x3, y3, z3 Fq

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
func (p *ErisPoint) Sub(arg1, arg2 *ErisPoint) *ErisPoint {
	var t ErisPoint
	t.Neg(arg2)
	return p.Add(arg1, &t)
}

// Double this point.
func (p *ErisPoint) Double(a *ErisPoint) (a2 *ErisPoint) {
	// Algorithm 9, https://eprint.iacr.org/2015/1060.pdf
	var t0, t1, t2, x3, y3, z3 Fq

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
func (p *ErisPoint) Mul(a *ErisPoint, s *Fp) *ErisPoint {
	bytes := s.Bytes()
	return p.multiply(a, &bytes)
}

func (p *ErisPoint) multiply(a *ErisPoint, bytes *[FieldBytes]byte) *ErisPoint {
	var t ErisPoint
	precomputed := [16]*ErisPoint{}
	precomputed[0] = new(ErisPoint).Identity()
	precomputed[1] = new(ErisPoint).Set(a)
	for i := 2; i < 16; i += 2 {
		precomputed[i] = new(ErisPoint).Double(precomputed[i>>1])
		precomputed[i+1] = new(ErisPoint).Add(precomputed[i], a)
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
func (p *ErisPoint) MulByU(a *ErisPoint) *ErisPoint {
	// Skip first bit since its always zero
	var s, t, r ErisPoint
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

func (p *ErisPoint) ClearCofactor(a *ErisPoint) *ErisPoint {
	p.Set(a)
	return p
}

// Neg negates this point.
func (p *ErisPoint) Neg(a *ErisPoint) *ErisPoint {
	p.Set(a)
	p.Y.CNeg(&a.Y, a.IsIdentity()^1)
	return p
}

// Set copies a into p.
func (p *ErisPoint) Set(a *ErisPoint) *ErisPoint {
	p.X.Set(&a.X)
	p.Y.Set(&a.Y)
	p.Z.Set(&a.Z)
	return p
}

// Nat returns the x and y as saferith.Nats in affine.
func (p *ErisPoint) Nat() (x, y *saferith.Nat) {
	var t ErisPoint
	t.ToAffine(p)
	return t.X.Nat(), t.Y.Nat()
}

// SetNat creates a point from affine x, y
// and returns the point if it is on the curve.
func (p *ErisPoint) SetNat(x, y *saferith.Nat) (*ErisPoint, error) {
	var xx, yy Fq
	var pp ErisPoint
	pp.X = *(xx.SetNat(x))
	pp.Y = *(yy.SetNat(y))

	if pp.X.IsZero()&pp.Y.IsZero() == 1 {
		pp.Identity()
		return p.Set(&pp), nil
	}

	pp.Z.SetOne()

	// If not the identity point and not on the curve then invalid
	if (pp.IsOnCurve()&pp.InCorrectSubgroup())|(xx.IsZero()&yy.IsZero()) == 0 {
		return nil, errs.NewCoordinates("invalid coordinates")
	}
	return p.Set(&pp), nil
}

// ToCompressed serialises this element into compressed form.
func (p *ErisPoint) ToCompressed() [FieldBytes]byte {
	var out [FieldBytes]byte
	var t ErisPoint
	t.ToAffine(p)
	xBytes := t.X.Bytes()
	copy(out[:], bitstring.ReverseBytes(xBytes[:]))
	isInfinity := byte(p.IsIdentity())
	// Is infinity
	out[0] |= isInfinity << 7
	// Sign of y only set if not infinity
	out[0] |= (byte(t.Y.LexicographicallyLargest()) << 6) & (isInfinity - 1)
	return out
}

// FromCompressed deserializes this element from compressed form.
func (p *ErisPoint) FromCompressed(input *[FieldBytes]byte) (*ErisPoint, error) {
	var xFp, yFp Fq
	var x [FieldBytes]byte
	var t ErisPoint

	infinityFlag := uint64((input[0] >> 7) & 1)
	sortFlag := uint64((input[0] >> 6) & 1)

	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		return p.Identity(), nil
	}

	copy(x[:], bitstring.ReverseBytes(input[:]))
	// Mask away the flag bits
	x[FieldBytes-1] &= 0x3F
	if _, valid := xFp.SetBytes(&x); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - not in field")
	}

	yFp.Square(&xFp)
	yFp.Mul(&yFp, &xFp)
	yFp.Add(&yFp, &erisB)

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
	return t.Set(&t), nil
}

// ToUncompressed serialises this element into uncompressed form.
func (*ErisPoint) ToUncompressed() [2 * FieldBytes]byte {
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
func (*ErisPoint) FromUncompressed(input *[2 * FieldBytes]byte) (*ErisPoint, error) {
	panic("not implemented")
	//var xFp, yFp Fp
	//var t [FieldBytes]byte
	//var p G1
	//infinityFlag := int((input[0] >> 6) & 1)
	//
	//if infinityFlag == 1 {
	//	return g1.Identity(), nil
	//}
	//
	//copy(t[:], bitstring.ReverseBytes(input[:FieldBytes]))
	//// Mask away top bits
	//t[FieldBytes-1] &= 0x1F
	//
	//_, valid := xFp.SetBytes(&t)
	//if valid == 0 {
	//	return nil, errs.NewFailed("invalid bytes - x not in field")
	//}
	//copy(t[:], bitstring.ReverseBytes(input[FieldBytes:]))
	//_, valid = yFp.SetBytes(&t)
	//if valid == 0 {
	//	return nil, errs.NewFailed("invalid bytes - y not in field")
	//}
	//
	//p.X.Set(&xFp)
	//p.Y.Set(&yFp)
	//p.Z.SetOne()
	//
	//if p.IsOnCurve() == 0 {
	//	return nil, errs.NewFailed("point is not on the curve")
	//}
	//if p.InCorrectSubgroup() == 0 {
	//	return nil, errs.NewFailed("point is not in correct subgroup")
	//}
	//return g1.Set(&p), nil
}

// ToAffine converts the point into affine coordinates.
func (p *ErisPoint) ToAffine(a *ErisPoint) *ErisPoint {
	var wasInverted uint64
	var zero, x, y, z Fq
	_, wasInverted = z.Invert(&a.Z)
	x.Mul(&a.X, &z)
	y.Mul(&a.Y, &z)

	p.X.CMove(&zero, &x, wasInverted)
	p.Y.CMove(&zero, &y, wasInverted)
	p.Z.CMove(&zero, z.SetOne(), wasInverted)
	return p
}

// GetX returns the affine X coordinate.
func (p *ErisPoint) GetX() *Fq {
	var x, zInv Fq
	zInv.Invert(&p.Z)
	x.Mul(&p.X, &zInv)
	return &x
}

// GetY returns the affine Y coordinate.
func (p *ErisPoint) GetY() *Fq {
	var y, zInv Fq
	zInv.Invert(&p.Z)
	y.Mul(&p.Y, &zInv)
	return &y
}

// Equal returns 1 if the two points are equal 0 otherwise.
func (p *ErisPoint) Equal(rhs *ErisPoint) uint64 {
	var x1, x2, y1, y2 Fq
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
func (p *ErisPoint) CMove(arg1, arg2 *ErisPoint, choice uint64) *ErisPoint {
	p.X.CMove(&arg1.X, &arg2.X, choice)
	p.Y.CMove(&arg1.Y, &arg2.Y, choice)
	p.Z.CMove(&arg1.Z, &arg2.Z, choice)
	return p
}
