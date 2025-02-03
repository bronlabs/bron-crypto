package points

import (
	"fmt"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
)

type TwistedEdwardsCurveParams[FP fields.FiniteField[FP]] interface {
	// SetGenerator sets generator coordinates.
	SetGenerator(xOut, yOut, tOut, zOut FP)

	// ClearCofactor clears cofactor (must comply with RFC9380).
	ClearCofactor(xOut, yOut, tOut, zOut, xIn, yIn, tIn, zIn FP)

	SetA(out FP)
	MulByA(out, in FP)
	MulByD(out, in FP)
	MulBy2D(out, in FP)
}

type TwistedEdwardsPointImpl[FP fields.FiniteFieldPtrConstraint[FP, F], C TwistedEdwardsCurveParams[FP], H h2c.HasherParams, M h2c.PointMapper[FP], F any] struct {
	X F
	Y F
	T F
	Z F
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Add(lhs, rhs *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	var params C
	var a, b, c, d, e, f, g, h, t0, t1, t2 F

	//  A = X1 * X2
	FP(&a).Mul(&lhs.X, &rhs.X)
	//  B = Y1 * Y2
	FP(&b).Mul(&lhs.Y, &rhs.Y)
	//  C = T1 * d * T2
	FP(&t0).Mul(&lhs.T, &rhs.T)
	params.MulByD(&c, &t0)
	//  D = Z1 * Z2
	FP(&d).Mul(&lhs.Z, &rhs.Z)
	//E = (X1+Y1)*(X2+Y2) - A - B
	FP(&t0).Add(&lhs.X, &lhs.Y)
	FP(&t1).Add(&rhs.X, &rhs.Y)
	FP(&t2).Mul(&t0, &t1)
	FP(&t0).Add(&a, &b)
	FP(&e).Sub(&t2, &t0)
	//  F = D - C
	FP(&f).Sub(&d, &c)
	//  G = D + C
	FP(&g).Add(&d, &c)
	//  H = B - a*A
	params.MulByA(&t0, &a)
	FP(&h).Sub(&b, &t0)
	// X3 = E * F
	FP(&p.X).Mul(&e, &f)
	// Y3 = G * H
	FP(&p.Y).Mul(&g, &h)
	// T3 = E * H
	FP(&p.T).Mul(&e, &h)
	// Z3 = F * G
	FP(&p.Z).Mul(&f, &g)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Double(v *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	var params C
	var a, b, c, d, e, f, g, h, t0, t1 F

	//  A = X1^2
	FP(&a).Square(&v.X)
	//  B = Y1^2
	FP(&b).Square(&v.Y)
	//  C = 2*Z1^2
	FP(&t0).Square(&v.Z)
	FP(&c).Add(&t0, &t0)
	//  D = a*A
	params.MulByA(&d, &a)
	//  E = (X1+Y1)^2-A-B
	FP(&t0).Add(&v.X, &v.Y)
	FP(&t1).Square(&t0)
	FP(&t0).Add(&a, &b)
	FP(&e).Sub(&t1, &t0)
	//  G = D+B
	FP(&g).Add(&d, &b)
	//  F = G-C
	FP(&f).Sub(&g, &c)
	//  H = D-B
	FP(&h).Sub(&d, &b)
	// X3 = E*F
	FP(&p.X).Mul(&e, &f)
	// Y3 = G*H
	FP(&p.Y).Mul(&g, &h)
	// T3 = E*H
	FP(&p.T).Mul(&e, &h)
	// Z3 = F*G
	FP(&p.Z).Mul(&f, &g)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Encode(dstPrefix string, message []byte) {
	var curveParams C
	var hasherParams H
	var mapper M

	var u [1]F
	h2c.HashToField[FP](u[:], hasherParams, dstPrefix, message)

	var xn, xd, yn, yd F
	mapper.Map(&xn, &xd, &yn, &yd, &u[0])

	var q TwistedEdwardsPointImpl[FP, C, H, M, F]
	q.setFractions(&xn, &xd, &yn, &yd)

	curveParams.ClearCofactor(&p.X, &p.Y, &p.T, &p.Z, &q.X, &q.Y, &q.T, &q.Z)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Hash(dst string, message []byte) {
	var curveParams C
	var hasherParams H
	var mapper M

	var u [2]F
	h2c.HashToField[FP](u[:], hasherParams, dst, message)

	var xn0, xd0, yn0, yd0, xn1, xd1, yn1, yd1 F
	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])
	mapper.Map(&xn1, &xd1, &yn1, &yd1, &u[1])

	var q0, q1 TwistedEdwardsPointImpl[FP, C, H, M, F]
	q0.setFractions(&xn0, &xd0, &yn0, &yd0)
	q1.setFractions(&xn1, &xd1, &yn1, &yd1)

	var q TwistedEdwardsPointImpl[FP, C, H, M, F]
	q.Add(&q0, &q1)

	curveParams.ClearCofactor(&p.X, &p.Y, &p.T, &p.Z, &q.X, &q.Y, &q.T, &q.Z)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Set(v *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	FP(&p.X).Set(&v.X)
	FP(&p.Y).Set(&v.Y)
	FP(&p.Z).Set(&v.Z)
	FP(&p.T).Set(&v.T)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) SetRandom(prng io.Reader) (ok uint64) {
	var curveParams C
	var mapper M

	var u [2]F
	ok0 := FP(&u[0]).SetRandom(prng)
	ok1 := FP(&u[1]).SetRandom(prng)
	ok = ok0 & ok1

	var xn0, xd0, yn0, yd0, xn1, xd1, yn1, yd1 F
	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])
	mapper.Map(&xn1, &xd1, &yn1, &yd1, &u[1])

	var q0, q1 TwistedEdwardsPointImpl[FP, C, H, M, F]
	q0.setFractions(&xn0, &xd0, &yn0, &yd0)
	q1.setFractions(&xn1, &xd1, &yn1, &yd1)

	var q TwistedEdwardsPointImpl[FP, C, H, M, F]
	q.Add(&q0, &q1)
	curveParams.ClearCofactor(&q.X, &q.Y, &q.T, &q.Z, &q.X, &q.Y, &q.T, &q.Z)

	p.Select(ok, p, &q)
	return ok
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) SetIdentity() {
	FP(&p.X).SetZero()
	FP(&p.Y).SetOne()
	FP(&p.Z).SetOne()
	FP(&p.T).SetZero()
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) SetGenerator() {
	var params C
	params.SetGenerator(&p.X, &p.Y, &p.T, &p.Z)
	FP(&p.Z).SetOne()
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) SetAffine(x, y FP) (ok uint64) {
	var params C
	var out TwistedEdwardsPointImpl[FP, C, H, M, F]
	FP(&out.X).Set(x)
	FP(&out.Y).Set(y)
	FP(&out.Z).SetOne()
	FP(&out.T).Mul(x, y)

	var one, xx, yy, l, r F
	FP(&one).SetOne()
	FP(&xx).Square(x)
	FP(&yy).Square(y)
	params.MulByA(&l, &xx)
	FP(&l).Add(&l, &yy)
	FP(&r).Mul(&xx, &yy)
	params.MulByD(&r, &r)
	FP(&r).Add(&r, &one)
	ok = FP(&l).Equals(&r)

	p.Select(ok, p, &out)
	return ok
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) SetFromAffineY(y FP) (ok uint64) {
	var params C
	var one, a, x, yy, num, den F
	var out TwistedEdwardsPointImpl[FP, C, H, M, F]

	FP(&one).SetOne()
	params.SetA(&a)
	FP(&yy).Square(y)
	FP(&num).Sub(&one, &yy)
	params.MulByD(&den, &yy)
	FP(&den).Sub(&a, &den)
	ok1 := FP(&den).Inv(&den)
	FP(&x).Mul(&num, &den)
	ok2 := FP(&x).Sqrt(&x)
	FP(&out.X).Set(&x)
	FP(&out.Y).Set(y)
	FP(&out.T).Mul(&x, y)
	FP(&out.Z).SetOne()

	ok = ok1 & ok2
	p.Select(ok, p, &out)
	return ok
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Select(choice uint64, z, nz *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	FP(&p.X).Select(choice, &z.X, &nz.X)
	FP(&p.Y).Select(choice, &z.Y, &nz.Y)
	FP(&p.Z).Select(choice, &z.Z, &nz.Z)
	FP(&p.T).Select(choice, &z.T, &nz.T)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) ClearCofactor(in *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	var params C

	params.ClearCofactor(&p.X, &p.Y, &p.T, &p.Z, &in.X, &in.Y, &in.T, &in.Z)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Sub(lhs, rhs *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	var rhsNeg TwistedEdwardsPointImpl[FP, C, H, M, F]
	rhsNeg.Neg(rhs)
	p.Add(lhs, &rhsNeg)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Neg(v *TwistedEdwardsPointImpl[FP, C, H, M, F]) {
	FP(&p.X).Neg(&v.X)
	FP(&p.Y).Set(&v.Y)
	FP(&p.Z).Set(&v.Z)
	FP(&p.T).Neg(&v.T)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) IsIdentity() uint64 {
	return FP(&p.X).IsZero() & (FP(&p.Y).Equals(&p.Z))
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) Equals(v *TwistedEdwardsPointImpl[FP, C, H, M, F]) uint64 {
	var x1z2, x2z1, y1z2, y2z1 F
	FP(&x1z2).Mul(&p.X, &v.Z)
	FP(&x2z1).Mul(&v.X, &p.Z)
	FP(&y1z2).Mul(&p.Y, &v.Z)
	FP(&y2z1).Mul(&v.Y, &p.Z)

	return FP(&x1z2).Equals(&x2z1) & FP(&y1z2).Equals(&y2z1)
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) ToAffine(x, y FP) (ok uint64) {
	var xx, yy, zInv F
	zInvPtr := FP(&zInv)
	ok = zInvPtr.Inv(&p.Z)

	FP(&xx).Mul(&p.X, zInvPtr)
	FP(&yy).Mul(&p.Y, zInvPtr)

	x.Select(ok, x, &xx)
	y.Select(ok, y, &yy)
	return ok
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) String() string {
	var one, x, y, z F
	FP(&one).SetOne()

	ok := p.ToAffine(&x, &y)
	FP(&x).Select(ok, &p.X, &x)
	FP(&y).Select(ok, &p.Y, &y)
	FP(&z).Select(ok, &p.Z, &one)

	return fmt.Sprintf("(%s : %s : %s)", FP(&x), FP(&y), FP(&z))
}

func (p *TwistedEdwardsPointImpl[FP, C, H, M, F]) setFractions(xn, xd, yn, yd FP) {
	FP(&p.X).Mul(xn, yd)
	FP(&p.Y).Mul(yn, xd)
	FP(&p.Z).Mul(xd, yd)
	FP(&p.T).Mul(xn, yn)
}
