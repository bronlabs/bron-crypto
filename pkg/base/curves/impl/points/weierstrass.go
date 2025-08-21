package points

import (
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
)

type ShortWeierstrassCurveParams[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	// SetGenerator sets generator coordinates.
	SetGenerator(xOut, yOut, zOut FP)

	// ClearCofactor clears cofactor (must comply with RFC9380).
	ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn FP)

	// AddA computes out = in + A, where A is the A in the curve equation y^2 = x^3 + Ax + B
	AddA(out FP, in FP)

	// AddB computes out = in + B, where B is the B in the curve equation y^2 = x^3 + Ax + B
	AddB(out FP, in FP)

	// MulByA computes out = in * A, where A is the A in the curve equation y^2 = x^3 + Ax + B
	MulByA(out FP, in FP)

	// MulBy3B computes out = in * 3 * B, where B is the B in the curve equation y^2 = x^3 + Ax + B
	MulBy3B(out FP, in FP)
}

type ShortWeierstrassPointImpl[FP fieldsImpl.FiniteFieldElementPtr[FP, F], C ShortWeierstrassCurveParams[FP], H h2c.HasherParams, M h2c.PointMapper[FP], F any] struct {
	X F
	Y F
	Z F

	base.IncomparableTrait
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Encode(dstPrefix string, message []byte) {
	var curveParams C
	var hasherParams H
	var mapper M

	var u [1]F
	h2c.HashToField[FP](u[:], hasherParams, dstPrefix, message)

	var xn, xd, yn, yd F
	mapper.Map(&xn, &xd, &yn, &yd, &u[0])

	var q ShortWeierstrassPointImpl[FP, C, H, M, F]
	q.setFractions(&xn, &xd, &yn, &yd)

	curveParams.ClearCofactor(&p.X, &p.Y, &p.Z, &q.X, &q.Y, &q.Z)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Hash(dst string, message []byte) {
	var curveParams C
	var hasherParams H
	var mapper M

	var u [2]F
	h2c.HashToField[FP](u[:], hasherParams, dst, message)

	var xn0, xd0, yn0, yd0, xn1, xd1, yn1, yd1 F
	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])
	mapper.Map(&xn1, &xd1, &yn1, &yd1, &u[1])

	var q0, q1 ShortWeierstrassPointImpl[FP, C, H, M, F]
	q0.setFractions(&xn0, &xd0, &yn0, &yd0)
	q1.setFractions(&xn1, &xd1, &yn1, &yd1)

	var q ShortWeierstrassPointImpl[FP, C, H, M, F]
	q.Add(&q0, &q1)

	curveParams.ClearCofactor(&p.X, &p.Y, &p.Z, &q.X, &q.Y, &q.Z)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Set(v *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	FP(&p.X).Set(&v.X)
	FP(&p.Y).Set(&v.Y)
	FP(&p.Z).Set(&v.Z)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) SetZero() {
	FP(&p.X).SetZero()
	FP(&p.Y).SetOne()
	FP(&p.Z).SetZero()
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) SetGenerator() {
	var params C

	params.SetGenerator(&p.X, &p.Y, &p.Z)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) SetRandom(prng io.Reader) (ok ct.Bool) {
	var curveParams C
	var mapper M

	var u [2]F
	ok0 := FP(&u[0]).SetRandom(prng)
	ok1 := FP(&u[1]).SetRandom(prng)
	ok = ok0 & ok1

	var xn0, xd0, yn0, yd0, xn1, xd1, yn1, yd1 F
	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])
	mapper.Map(&xn1, &xd1, &yn1, &yd1, &u[1])

	var q0, q1 ShortWeierstrassPointImpl[FP, C, H, M, F]
	q0.setFractions(&xn0, &xd0, &yn0, &yd0)
	q1.setFractions(&xn1, &xd1, &yn1, &yd1)

	var q ShortWeierstrassPointImpl[FP, C, H, M, F]
	q.Add(&q0, &q1)
	curveParams.ClearCofactor(&q.X, &q.Y, &q.Z, &q.X, &q.Y, &q.Z)

	p.Select(ok, p, &q)
	return ok
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) SetAffine(x, y FP) (ok ct.Bool) {
	var params C
	var one, eql, eqr F
	FP(&one).SetOne()

	FP(&eqr).Square(x)
	params.AddA(&eqr, &eqr)
	FP(&eqr).Mul(&eqr, x)
	params.AddB(&eqr, &eqr)

	FP(&eql).Square(y)
	ok = FP(&eql).Equal(&eqr)

	FP(&p.X).Select(ok, &p.X, x)
	FP(&p.Y).Select(ok, &p.Y, y)
	FP(&p.Z).Select(ok, &p.Z, &one)
	return ok
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) setFractions(xn, xd, yn, yd FP) {
	FP(&p.X).Mul(xn, yd)
	FP(&p.Y).Mul(yn, xd)
	FP(&p.Z).Mul(xd, yd)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) SetFromAffineX(x FP) (ok ct.Bool) {
	var params C
	var one, yy, y F
	FP(&one).SetOne()

	FP(&yy).Square(x)
	params.AddA(&yy, &yy)
	FP(&yy).Mul(&yy, x)
	params.AddB(&yy, &yy)
	ok = FP(&y).Sqrt(&yy)

	FP(&p.X).Select(ok, &p.X, x)
	FP(&p.Y).Select(ok, &p.Y, &y)
	FP(&p.Z).Select(ok, &p.Z, &one)
	return ok
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Select(choice ct.Choice, z, nz *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	FP(&p.X).Select(choice, &z.X, &nz.X)
	FP(&p.Y).Select(choice, &z.Y, &nz.Y)
	FP(&p.Z).Select(choice, &z.Z, &nz.Z)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) ClearCofactor(in *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	var params C

	params.ClearCofactor(&p.X, &p.Y, &p.Z, &in.Z, &in.Y, &in.Z)
}

// Add computes p = lhs + rhs
// Source: 2015 Renes–Costello–Batina "Complete addition formulas for prime order elliptic curves", Appendix A.1.
func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Add(lhs, rhs *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	var arith C
	var t0f, t1f, t2f, t3f, t4f, t5f F
	var x3f, y3f, z3f F

	t0 := FP(&t0f)
	t1 := FP(&t1f)
	t2 := FP(&t2f)
	t3 := FP(&t3f)
	t4 := FP(&t4f)
	t5 := FP(&t5f)
	x1 := FP(&lhs.X)
	y1 := FP(&lhs.Y)
	z1 := FP(&lhs.Z)
	x2 := FP(&rhs.X)
	y2 := FP(&rhs.Y)
	z2 := FP(&rhs.Z)
	x3 := FP(&x3f)
	y3 := FP(&y3f)
	z3 := FP(&z3f)

	t0.Mul(x1, x2)
	t1.Mul(y1, y2)
	t2.Mul(z1, z2)
	t3.Add(x1, y1)
	t4.Add(x2, y2)
	t3.Mul(t3, t4)
	t4.Add(t0, t1)
	t3.Sub(t3, t4)
	t4.Add(x1, z1)
	t5.Add(x2, z2)
	t4.Mul(t4, t5)
	t5.Add(t0, t2)
	t4.Sub(t4, t5)
	t5.Add(y1, z1)
	x3.Add(y2, z2)
	t5.Mul(t5, x3)
	x3.Add(t1, t2)
	t5.Sub(t5, x3)
	arith.MulByA(z3, t4)
	arith.MulBy3B(x3, t2)
	z3.Add(x3, z3)
	x3.Sub(t1, z3)
	z3.Add(t1, z3)
	y3.Mul(x3, z3)
	t1.Add(t0, t0)
	t1.Add(t1, t0)
	arith.MulByA(t2, t2)
	arith.MulBy3B(t4, t4)
	t1.Add(t1, t2)
	t2.Sub(t0, t2)
	arith.MulByA(t2, t2)
	t4.Add(t4, t2)
	t0.Mul(t1, t4)
	y3.Add(y3, t0)
	t0.Mul(t5, t4)
	x3.Mul(t3, x3)
	x3.Sub(x3, t0)
	t0.Mul(t3, t1)
	z3.Mul(t5, z3)
	z3.Add(z3, t0)

	FP(&p.X).Set(x3)
	FP(&p.Y).Set(y3)
	FP(&p.Z).Set(z3)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Sub(lhs, rhs *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	var rhsNeg ShortWeierstrassPointImpl[FP, C, H, M, F]
	rhsNeg.Neg(rhs)
	p.Add(lhs, &rhsNeg)
}

// Double computes p = v + v
// Source: 2015 Renes–Costello–Batina "Complete addition formulas for prime order elliptic curves", Appendix A.1.
// The Bernstein–Lange doubling might be slightly faster, but these are highly unified.
func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Double(v *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	var arith C
	var t0f, t1f, t2f, t3f F
	var x3f, y3f, z3f F

	t0 := FP(&t0f)
	t1 := FP(&t1f)
	t2 := FP(&t2f)
	t3 := FP(&t3f)
	x1 := FP(&v.X)
	y1 := FP(&v.Y)
	z1 := FP(&v.Z)
	x3 := FP(&x3f)
	y3 := FP(&y3f)
	z3 := FP(&z3f)

	t0.Square(x1)
	t1.Square(y1)
	t2.Square(z1)
	t3.Mul(x1, y1)
	t3.Add(t3, t3)
	z3.Mul(x1, z1)
	z3.Add(z3, z3)
	arith.MulByA(x3, z3)
	arith.MulBy3B(y3, t2)
	y3.Add(x3, y3)
	x3.Sub(t1, y3)
	y3.Add(t1, y3)
	y3.Mul(x3, y3)
	x3.Mul(t3, x3)
	arith.MulBy3B(z3, z3)
	arith.MulByA(t2, t2)
	t3.Sub(t0, t2)
	arith.MulByA(t3, t3)
	t3.Add(t3, z3)
	z3.Add(t0, t0)
	t0.Add(z3, t0)
	t0.Add(t0, t2)
	t0.Mul(t0, t3)
	y3.Add(y3, t0)
	t2.Mul(y1, z1)
	t2.Add(t2, t2)
	t0.Mul(t2, t3)
	x3.Sub(x3, t0)
	z3.Mul(t2, t1)
	z3.Add(z3, z3)
	z3.Add(z3, z3)

	p.X = *x3
	p.Y = *y3
	p.Z = *z3
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Neg(v *ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	FP(&p.X).Set(&v.X)
	FP(&p.Y).Neg(&v.Y)
	FP(&p.Z).Set(&v.Z)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) IsZero() ct.Bool {
	return FP(&p.Z).IsZero()
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) IsNonZero() ct.Bool {
	return FP(&p.Z).IsNonZero()
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Equal(rhs *ShortWeierstrassPointImpl[FP, C, H, M, F]) ct.Bool {
	var x1z2f, y1z2f, x2z1f, y2z1f F
	x1z2 := FP(&x1z2f)
	y1z2 := FP(&y1z2f)
	x2z1 := FP(&x2z1f)
	y2z1 := FP(&y2z1f)

	x1 := FP(&p.X)
	y1 := FP(&p.Y)
	z1 := FP(&p.Z)
	x2 := FP(&rhs.X)
	y2 := FP(&rhs.Y)
	z2 := FP(&rhs.Z)

	x1z2.Mul(x1, z2)
	y1z2.Mul(y1, z2)
	x2z1.Mul(x2, z1)
	y2z1.Mul(y2, z1)

	return x1z2.Equal(x2z1) & y1z2.Equal(y2z1)
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) ToAffine(xOut, yOut FP) (ok ct.Bool) {
	var x, y, zInv F
	zInvPtr := FP(&zInv)
	ok = zInvPtr.Inv(&p.Z)

	FP(&x).Mul(&p.X, zInvPtr)
	FP(&y).Mul(&p.Y, zInvPtr)

	xOut.Select(ok, xOut, &x)
	yOut.Select(ok, yOut, &y)
	return ok
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) String() string {
	var one, x, y, z F
	FP(&one).SetOne()

	ok := p.ToAffine(&x, &y)
	FP(&x).Select(ok, &p.X, &x)
	FP(&y).Select(ok, &p.Y, &y)
	FP(&z).Select(ok, &p.Z, &one)

	return fmt.Sprintf("(%s : %s : %s)", FP(&x), FP(&y), FP(&z))
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) Bytes() []byte {
	return slices.Concat(FP(&p.X).Bytes(), FP(&p.Y).Bytes(), FP(&p.Z).Bytes())
}

func (p *ShortWeierstrassPointImpl[FP, C, H, M, F]) SetBytes(input []byte) (ok ct.Bool) {
	coordinateLen := len(input) / 3
	x := input[:coordinateLen]
	y := input[coordinateLen : 2*coordinateLen]
	z := input[2*coordinateLen:]

	var tmpX, tmpY, tmpZ F
	okX := FP(&tmpX).SetBytes(x)
	okY := FP(&tmpY).SetBytes(y)
	okZ := FP(&tmpZ).SetBytes(z)
	ok = okX & okY & okZ

	// Conditionally assign: keep current if failed
	FP(&p.X).Select(ok, &p.X, &tmpX)
	FP(&p.Y).Select(ok, &p.Y, &tmpY)
	FP(&p.Z).Select(ok, &p.Z, &tmpZ)
	return ok
}
