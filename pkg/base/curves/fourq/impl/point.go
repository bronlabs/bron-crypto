package impl

import (
	"encoding/hex"
	"slices"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	coefficientD Fp2
	coefficientK Fp2
	gx, gy       Fp2
)

type ExtendedPoint struct {
	X, Y, Z, T Fp2

	_ ds.Incomparable
}

//nolint:gochecknoinits // prototype
func init() {
	dBytes, _ := hex.DecodeString("5e472f846657e0fcb3821488f1fc0c8d00000000000000e40000000000000142")
	slices.Reverse(dBytes)
	coefficientD.FromBytes(dBytes)
	coefficientK.Add(&coefficientD, &coefficientD)

	gxBytes, _ := hex.DecodeString("1E1F553F2878AA9C96869FB360AC77F61A3472237C2FB305286592AD7B3833AA")
	gyBytes, _ := hex.DecodeString("6E1C4AF8630E024249A7C344844C8B5C0E3FEE9BA120785AB924A2462BCBB287")
	slices.Reverse(gxBytes)
	slices.Reverse(gyBytes)
	gx.FromBytes(gxBytes)
	gy.FromBytes(gyBytes)
}

// Identity returns the identity point.
func (p *ExtendedPoint) Identity() *ExtendedPoint {
	p.X.SetZero()
	p.Y.SetOne()
	p.Z.SetOne()
	p.T.SetZero()
	return p
}

// Generator returns the base point.
func (p *ExtendedPoint) Generator() *ExtendedPoint {
	p.X = gx
	p.Y = gy
	p.Z.SetOne()
	p.T.Mul(&gx, &gy)
	return p
}

// IsIdentity returns true if this point is at infinity.
func (p *ExtendedPoint) IsIdentity() uint64 {
	return p.X.IsZero()
}

// IsOnCurve determines if this point represents a valid curve point.
func (*ExtendedPoint) IsOnCurve() uint64 {
	panic("implement me")
}

// InCorrectSubgroup returns 1 if the point is torsion free, 0 otherwise.
func (*ExtendedPoint) InCorrectSubgroup() uint64 {
	return 1
}

// Add adds this point to another point.
func (p *ExtendedPoint) Add(arg1, arg2 *ExtendedPoint) *ExtendedPoint {
	// 2008 Hisil–Wong–Carter–Dawson, http://eprint.iacr.org/2008/522, Section 3.1.
	a := new(Fp2).Mul(new(Fp2).Sub(&arg1.Y, &arg1.X), new(Fp2).Sub(&arg2.Y, &arg2.X))
	b := new(Fp2).Mul(new(Fp2).Add(&arg1.Y, &arg1.X), new(Fp2).Add(&arg2.Y, &arg2.X))
	c := new(Fp2).Mul(new(Fp2).Mul(&arg1.T, &arg2.T), &coefficientK)
	d := new(Fp2).Mul(&arg1.Z, new(Fp2).Add(&arg2.Z, &arg2.Z))
	e := new(Fp2).Sub(b, a)
	f := new(Fp2).Sub(d, c)
	g := new(Fp2).Add(d, c)
	h := new(Fp2).Add(b, a)
	p.X.Mul(e, f)
	p.Y.Mul(g, h)
	p.T.Mul(e, h)
	p.Z.Mul(f, g)
	return p
}

// Sub subtracts the two points.
func (p *ExtendedPoint) Sub(arg1, arg2 *ExtendedPoint) *ExtendedPoint {
	var t ExtendedPoint
	t.Neg(arg2)
	return p.Add(arg1, &t)
}

// Double this point.
func (p *ExtendedPoint) Double(arg *ExtendedPoint) *ExtendedPoint {
	// 2008 Hisil–Wong–Carter–Dawson, http://eprint.iacr.org/2008/522, Section 3.3.
	a := new(Fp2).Square(&arg.X)
	b := new(Fp2).Square(&arg.Y)
	c := new(Fp2).Square(&arg.Z)
	c = c.Add(c, c)
	d := new(Fp2).Neg(a)
	e := new(Fp2).Sub(new(Fp2).Sub(new(Fp2).Square(new(Fp2).Add(&arg.X, &arg.Y)), a), b)
	g := new(Fp2).Add(d, b)
	f := new(Fp2).Sub(g, c)
	h := new(Fp2).Sub(d, b)
	p.X.Mul(e, f)
	p.Y.Mul(g, h)
	p.T.Mul(e, h)
	p.Z.Mul(f, g)
	return p
}

// Mul multiplies this point by the input scalar.
func (p *ExtendedPoint) Mul(a *ExtendedPoint, s *[4]uint64) *ExtendedPoint {
	// TODO: there are faster algorithms
	var tmp, res ExtendedPoint
	res.Identity()

	for i := len(s) - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			res.Double(&res)
			tmp.Add(&res, a)
			res.CMove(&res, &tmp, (s[i]>>j)&1)
		}
	}

	*p = res
	return p
}

func (p *ExtendedPoint) ClearCofactor(a *ExtendedPoint) *ExtendedPoint {
	p1 := new(ExtendedPoint).Double(a)  // [2]A
	p2 := new(ExtendedPoint).Add(p1, a) // [3]A
	p3 := new(ExtendedPoint).Double(p2) // [6]A
	p3 = p3.Double(p3)                  // 12[A]
	p3 = p3.Double(p3)                  // 24[A]
	p3 = p3.Double(p3)                  // 48[A]
	q := new(ExtendedPoint).Add(p3, a)  // 49[A]
	q = q.Double(q)                     // 98[A]
	q = q.Double(q)                     // 196[A]
	p.Double(q)                         // 392[A]
	return p
}

// Neg negates this point.
func (p *ExtendedPoint) Neg(a *ExtendedPoint) *ExtendedPoint {
	p.X.Neg(&a.X)
	p.Y = a.Y
	p.Z = a.Z
	p.T.Neg(&a.T)
	return p
}

// Set copies a into g1.
func (p *ExtendedPoint) Set(a *ExtendedPoint) *ExtendedPoint {
	*p = *a
	return p
}

// ToCompressed serialises this element into compressed form.
func (p *ExtendedPoint) ToCompressed() []byte {
	affine := new(ExtendedPoint).ToAffine(p)
	x := affine.GetX()
	xNeg := new(Fp2).Neg(x)
	y := affine.GetY()
	sign := xNeg.IsLexicographicallyGreater(x)

	yBytes := y.ToBytes()
	yBytes[31] |= byte(sign) << 7
	return yBytes
}

// FromCompressed deserializes this element from compressed form.
func (p *ExtendedPoint) FromCompressed(input []byte) (*ExtendedPoint, error) {
	var buf [32]byte
	copy(buf[:], input)

	s := uint64(buf[31] >> 7)
	buf[31] &= 0x7f
	y := new(Fp2).FromBytes(buf[:])

	yy := new(Fp2).Square(y)
	nom := new(Fp2).Sub(yy, &Fp2One)
	den := new(Fp2).Add(new(Fp2).Mul(&coefficientD, yy), &Fp2One)
	denInv, ok := new(Fp2).Inv(den)
	if ok != 1 {
		return nil, errs.NewSerialisation("invalid point")
	}
	xx := new(Fp2).Mul(nom, denInv)
	x, ok2 := new(Fp2).Sqrt(xx)
	if ok2 != 1 {
		return nil, errs.NewSerialisation("invalid point")
	}
	xNeg := new(Fp2).Neg(x)
	xs := x.IsLexicographicallyGreater(xNeg)

	p.X.CMove(xNeg, x, s^xs)
	p.Y = *y
	p.Z.SetOne()
	p.T.Mul(&p.X, &p.Y)
	return p, nil
}

// ToAffine converts the point into affine coordinates.
func (p *ExtendedPoint) ToAffine(a *ExtendedPoint) *ExtendedPoint {
	var zInv Fp2
	zInv.Inv(&a.Z)

	p.X.Mul(&a.X, &zInv)
	p.Y.Mul(&a.Y, &zInv)
	p.Z.SetOne()
	p.T.Mul(&a.T, &zInv)
	return p
}

// GetX returns the affine X coordinate.
func (p *ExtendedPoint) GetX() *Fp2 {
	return &p.X
}

// GetY returns the affine Y coordinate.
func (p *ExtendedPoint) GetY() *Fp2 {
	return &p.Y
}

// Equal returns 1 if the two points are equal 0 otherwise.
func (p *ExtendedPoint) Equal(rhs *ExtendedPoint) uint64 {
	var x1z2, x2z1, y1z2, y2z1 Fp2

	x1z2.Mul(&p.X, &rhs.Z)
	x2z1.Mul(&rhs.X, &p.Z)
	y1z2.Mul(&p.Y, &rhs.Z)
	y2z1.Mul(&rhs.Y, &p.Z)

	return x1z2.Equal(&x2z1) & y1z2.Equal(&y2z1)
}

func (p *ExtendedPoint) CMove(arg1, arg2 *ExtendedPoint, choice uint64) *ExtendedPoint {
	p.X.CMove(&arg1.X, &arg2.X, choice)
	p.Y.CMove(&arg1.Y, &arg2.Y, choice)
	p.Z.CMove(&arg1.Z, &arg2.Z, choice)
	p.T.CMove(&arg1.T, &arg2.T, choice)
	return p
}
