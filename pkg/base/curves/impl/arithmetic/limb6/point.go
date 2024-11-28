package limb6

import (
	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

// EllipticPoint represents a Weierstrauss elliptic curve point.
type EllipticPoint struct {
	X          *FieldValue
	Y          *FieldValue
	Z          *FieldValue
	Params     *EllipticPointParams
	Arithmetic EllipticPointArithmetic

	_ ds.Incomparable
}

// EllipticPointParams are the Weierstrauss curve parameters
// such as the name, the coefficients the generator point,
// and the prime bit size.
type EllipticPointParams struct {
	Name    string
	A       *FieldValue
	B       *FieldValue
	Gx      *FieldValue
	Gy      *FieldValue
	BitSize int

	_ ds.Incomparable
}

// EllipticPointArithmetic are the methods that specific curves
// need to implement for higher abstractions to wrap the point.
type EllipticPointArithmetic interface {
	// Map convert two field elements u0 and u1 into a point
	Map(u0, u1 *FieldValue, out *EllipticPoint) error
	// Double arg and store the result in out
	Double(out, arg *EllipticPoint)
	// Add arg1 with arg2 and store the result in out
	Add(out, arg1, arg2 *EllipticPoint)
	// IsOnCurve tests arg if it represents a valid point on the curve
	IsOnCurve(arg *EllipticPoint) bool
	// ToAffine converts arg to affine coordinates storing the result in out
	ToAffine(out, arg *EllipticPoint)
	// RhsEquation computes the right-hand side of the ecc equation
	RhsEquation(out, x *FieldValue)
}

// Identity returns the identity point.
func (p *EllipticPoint) Identity() *EllipticPoint {
	p.X.SetZero()
	p.Y.SetOne()
	p.Z.SetZero()
	return p
}

// Generator returns the base point for the curve.
func (p *EllipticPoint) Generator() *EllipticPoint {
	p.X.Set(p.Params.Gx)
	p.Y.Set(p.Params.Gy)
	p.Z.SetOne()
	return p
}

// IsIdentity returns true if this point is at infinity.
func (p *EllipticPoint) IsIdentity() bool {
	return p.Z.IsZero() == 1
}

// Double this point.
func (p *EllipticPoint) Double(point *EllipticPoint) *EllipticPoint {
	p.Set(point)
	p.Arithmetic.Double(p, point)
	return p
}

// Neg negates this point.
func (p *EllipticPoint) Neg(point *EllipticPoint) *EllipticPoint {
	p.Set(point)
	p.Y.Neg(p.Y)
	return p
}

// Add adds the two points.
func (p *EllipticPoint) Add(lhs, rhs *EllipticPoint) *EllipticPoint {
	p.Set(lhs)
	p.Arithmetic.Add(p, lhs, rhs)
	return p
}

// Sub subtracts the two points.
func (p *EllipticPoint) Sub(lhs, rhs *EllipticPoint) *EllipticPoint {
	p.Set(lhs)
	p.Arithmetic.Add(p, lhs, new(EllipticPoint).Neg(rhs))
	return p
}

// Mul multiplies this point by the input scalar.
func (p *EllipticPoint) Mul(point *EllipticPoint, scalar *FieldValue) *EllipticPoint {
	bytes := scalar.Bytes()
	precomputed := [16]*EllipticPoint{}
	precomputed[0] = new(EllipticPoint).Set(point).Identity()
	precomputed[1] = new(EllipticPoint).Set(point)
	for i := 2; i < 16; i += 2 {
		precomputed[i] = new(EllipticPoint).Set(point).Double(precomputed[i>>1])
		precomputed[i+1] = new(EllipticPoint).Set(point).Add(precomputed[i], point)
	}
	pos := p.Params.BitSize - 4
	p.Identity()
	t := new(EllipticPoint).Set(point)
	for ; pos >= 0; pos -= 4 {
		for i := 0; i < 4; i++ {
			p.Double(p)
		}
		slot := (bytes[pos>>3] >> (pos & 7)) & 0xf
		t.Identity()
		for i := 1; i < 16; i++ {
			choice := (((safecast.ToUint64(slot) ^ safecast.ToUint64(i)) - 1) >> 8) & 1
			t.CMove(t, precomputed[i], choice)
		}

		p.Add(p, t)
	}

	return p
}

// Equal returns 1 if the two points are equal 0 otherwise.
func (p *EllipticPoint) Equal(rhs *EllipticPoint) uint64 {
	var x1, x2, y1, y2 FieldValue

	x1.Arithmetic = p.X.Arithmetic
	x2.Arithmetic = p.X.Arithmetic
	y1.Arithmetic = p.Y.Arithmetic
	y2.Arithmetic = p.Y.Arithmetic

	x1.Mul(p.X, rhs.Z)
	x2.Mul(rhs.X, p.Z)

	y1.Mul(p.Y, rhs.Z)
	y2.Mul(rhs.Y, p.Z)

	e1 := p.Z.IsZero()
	e2 := rhs.Z.IsZero()

	// Both at infinity or coordinates are the same
	return (e1 & e2) | (^e1 & ^e2)&x1.Equal(&x2)&y1.Equal(&y2)
}

// Set copies clone into p.
func (p *EllipticPoint) Set(clone *EllipticPoint) *EllipticPoint {
	p.X = new(FieldValue).Set(clone.X)
	p.Y = new(FieldValue).Set(clone.Y)
	p.Z = new(FieldValue).Set(clone.Z)
	p.Params = clone.Params
	p.Arithmetic = clone.Arithmetic
	return p
}

// Nat returns the x and y as saferith.Nat in affine.
func (p *EllipticPoint) Nat() (x, y *saferith.Nat) {
	t := new(EllipticPoint).Set(p)
	p.Arithmetic.ToAffine(t, p)
	x = t.X.Nat()
	y = t.Y.Nat()
	return x, y
}

// SetNat creates a point from affine x, y
// and returns the point if it is on the curve.
func (p *EllipticPoint) SetNat(x, y *saferith.Nat) (*EllipticPoint, error) {
	xx := &FieldValue{
		Params:     p.Params.Gx.Params,
		Arithmetic: p.Params.Gx.Arithmetic,
	}
	xx.SetNat(x)
	yy := &FieldValue{
		Params:     p.Params.Gx.Params,
		Arithmetic: p.Params.Gx.Arithmetic,
	}
	yy.SetNat(y)
	pp := new(EllipticPoint).Set(p)

	zero := new(FieldValue).Set(xx).SetZero()
	one := new(FieldValue).Set(xx).SetOne()
	isIdentity := xx.IsZero() & yy.IsZero()
	pp.X = xx.CMove(xx, zero, isIdentity)
	pp.Y = yy.CMove(yy, zero, isIdentity)
	pp.Z = one.CMove(one, zero, isIdentity)
	if !p.Arithmetic.IsOnCurve(pp) && isIdentity == 0 {
		return nil, errs.NewCoordinates("set Nat")
	}
	return p.Set(pp), nil
}

// GetX returns the affine X coordinate.
func (p *EllipticPoint) GetX() *FieldValue {
	t := new(EllipticPoint).Set(p)
	p.Arithmetic.ToAffine(t, p)
	return t.X
}

// GetY returns the affine Y coordinate.
func (p *EllipticPoint) GetY() *FieldValue {
	t := new(EllipticPoint).Set(p)
	p.Arithmetic.ToAffine(t, p)
	return t.Y
}

// IsOnCurve determines if this point represents a valid curve point.
func (p *EllipticPoint) IsOnCurve() bool {
	return p.Arithmetic.IsOnCurve(p)
}

// ToAffine converts the point into affine coordinates.
func (p *EllipticPoint) ToAffine(clone *EllipticPoint) *EllipticPoint {
	p.Arithmetic.ToAffine(p, clone)
	return p
}

// SumOfProducts computes the multi-exponentiation for the specified
// points and scalars and stores the result in `p`.
// Returns an error if the lengths of the arguments is not equal.
func (p *EllipticPoint) SumOfProducts(points []*EllipticPoint, scalars []*FieldValue) (*EllipticPoint, error) {
	const Upper = 256
	const W = 4
	const Windows = Upper / W // careful--use ceiling division in case this doesn't divide evenly
	if len(points) != len(scalars) {
		return nil, errs.NewSize("#points != #scalars")
	}

	bucketSize := 1 << W
	windows := make([]*EllipticPoint, Windows)
	bytes := make([][48]byte, len(scalars))
	buckets := make([]*EllipticPoint, bucketSize)

	for i, scalar := range scalars {
		bytes[i] = scalar.Bytes()
	}
	for i := range windows {
		windows[i] = new(EllipticPoint).Set(p).Identity()
	}

	for i := 0; i < bucketSize; i++ {
		buckets[i] = new(EllipticPoint).Set(p).Identity()
	}

	sum := new(EllipticPoint).Set(p)

	for j := 0; j < len(windows); j++ {
		for i := 0; i < bucketSize; i++ {
			buckets[i].Identity()
		}

		for i := 0; i < len(scalars); i++ {
			// j*W to get the nibble
			// >> 3 to convert to byte, / 8
			// (W * j & W) gets the nibble, mod W
			// 1 << W - 1 to get the offset
			index := bytes[i][j*W>>3] >> (W * j & W) & (1<<W - 1) // little-endian
			buckets[index].Add(buckets[index], points[i])
		}

		sum.Identity()

		for i := bucketSize - 1; i > 0; i-- {
			sum.Add(sum, buckets[i])
			windows[j].Add(windows[j], sum)
		}
	}

	p.Identity()
	for i := len(windows) - 1; i >= 0; i-- {
		for j := 0; j < W; j++ {
			p.Double(p)
		}

		p.Add(p, windows[i])
	}
	return p, nil
}

// CMove returns arg1 if choice == 0, otherwise returns arg2.
func (*EllipticPoint) CMove(pt1, pt2 *EllipticPoint, choice uint64) *EllipticPoint {
	pt1.X.CMove(pt1.X, pt2.X, choice)
	pt1.Y.CMove(pt1.Y, pt2.Y, choice)
	pt1.Z.CMove(pt1.Z, pt2.Z, choice)
	return pt1
}
