package impl

import (
	"io"

	filippo "filippo.io/edwards25519"
	filippoField "filippo.io/edwards25519/field"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

var _ pointsImpl.PointPtr[*Fp, *Point] = (*Point)(nil)

type Point struct {
	V filippo.Point
}

func (p *Point) Encode(dstPrefix string, message []byte) {
	var hasherParams CurveHasherParams
	var mapper CurveMapper

	var u [1]Fp
	h2c.HashToField[*Fp](u[:], hasherParams, dstPrefix, message)

	var xn0, xd0, yn0, yd0 Fp
	var x, y, z, t Fp

	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])
	x.Mul(&xn0, &yd0)
	y.Mul(&yn0, &xd0)
	z.Mul(&xd0, &yd0)
	t.Mul(&xn0, &yn0)

	var q filippo.Point
	_, err := q.SetExtendedCoordinates(&x.V, &y.V, &z.V, &t.V)
	if err != nil {
		panic("this should never happen")
	}

	q.MultByCofactor(&q)
	p.V.Set(&q)
}

func (p *Point) Hash(dstPrefix string, message []byte) {
	var hasherParams CurveHasherParams
	var mapper CurveMapper

	var u [2]Fp
	h2c.HashToField[*Fp](u[:], hasherParams, dstPrefix, message)

	var xn0, xd0, yn0, yd0 Fp
	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])

	var x, y, z, t Fp
	x.Mul(&xn0, &yd0)
	y.Mul(&yn0, &xd0)
	z.Mul(&xd0, &yd0)
	t.Mul(&xn0, &yn0)

	var q, q0, q1 filippo.Point
	_, err := q0.SetExtendedCoordinates(&x.V, &y.V, &z.V, &t.V)
	if err != nil {
		panic("this should never happen")
	}

	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[1])
	x.Mul(&xn0, &yd0)
	y.Mul(&yn0, &xd0)
	z.Mul(&xd0, &yd0)
	t.Mul(&xn0, &yn0)

	_, err = q1.SetExtendedCoordinates(&x.V, &y.V, &z.V, &t.V)
	if err != nil {
		panic("this should never happen")
	}

	q.Add(&q0, &q1)
	q.MultByCofactor(&q)
	p.V.Set(&q)
}

func (p *Point) Set(v *Point) {
	p.V.Set(&v.V)
}

func (p *Point) SetRandom(prng io.Reader) (ok uint64) {
	var mapper CurveMapper

	var u [2]Fp
	ok = u[0].SetRandom(prng)
	if ok != 1 {
		return 0
	}
	ok = u[1].SetRandom(prng)
	if ok != 1 {
		return 0
	}

	var xn0, xd0, yn0, yd0 Fp
	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[0])

	var x, y, z, t Fp
	x.Mul(&xn0, &yd0)
	y.Mul(&yn0, &xd0)
	z.Mul(&xd0, &yd0)
	t.Mul(&xn0, &yn0)

	var q, q0, q1 filippo.Point
	_, err := q0.SetExtendedCoordinates(&x.V, &y.V, &z.V, &t.V)
	if err != nil {
		panic("this should never happen")
	}

	mapper.Map(&xn0, &xd0, &yn0, &yd0, &u[1])
	x.Mul(&xn0, &yd0)
	y.Mul(&yn0, &xd0)
	z.Mul(&xd0, &yd0)
	t.Mul(&xn0, &yn0)

	_, err = q1.SetExtendedCoordinates(&x.V, &y.V, &z.V, &t.V)
	if err != nil {
		panic("this should never happen")
	}

	q.Add(&q0, &q1)
	q.MultByCofactor(&q)
	p.V.Set(&q)
	return 1
}

func (p *Point) SetIdentity() {
	p.V.Set(filippo.NewIdentityPoint())
}

func (p *Point) SetGenerator() {
	p.V.Set(filippo.NewGeneratorPoint())
}

func (p *Point) SetAffine(x, y *Fp) (ok uint64) {
	var z, t filippoField.Element
	z.One()
	t.Multiply(&x.V, &y.V)
	_, err := p.V.SetExtendedCoordinates(&x.V, &y.V, &z, &t)
	if err != nil {
		return 0
	}

	return 1
}

func (p *Point) Select(choice uint64, z, nz *Point) {
	// yes, filippo is not constant time
	if choice == 0 {
		p.V = z.V
	} else {
		p.V = nz.V
	}
}

func (p *Point) Add(lhs, rhs *Point) {
	p.V.Add(&lhs.V, &rhs.V)
}

func (p *Point) Sub(lhs, rhs *Point) {
	p.V.Subtract(&lhs.V, &rhs.V)
}

func (p *Point) Neg(v *Point) {
	p.V.Negate(&v.V)
}

func (p *Point) Double(v *Point) {
	p.V.Add(&v.V, &v.V)
}

func (p *Point) IsIdentity() uint64 {
	return uint64(p.V.Equal(filippo.NewIdentityPoint()))
}

func (p *Point) Equals(v *Point) uint64 {
	return uint64(p.V.Equal(&v.V))
}

func (p *Point) ToAffine(x, y *Fp) (ok uint64) {
	var zero, zInv filippoField.Element
	xx, yy, zz, _ := p.V.ExtendedCoordinates()
	zInv.Invert(zz)

	x.V.Multiply(xx, &zInv)
	y.V.Multiply(yy, &zInv)
	return uint64(zInv.Equal(zero.Zero()) ^ 1)
}

func (p *Point) ScalarMul(lhs *Point, scalar *Fq) {
	p.V.ScalarMult(&scalar.V, &lhs.V)
}

func (p *Point) ScalarBaseMul(scalar *Fq) {
	p.V.ScalarBaseMult(&scalar.V)
}

func (p *Point) ClearCofactor(v *Point) {
	p.V.MultByCofactor(&v.V)
}

func (p *Point) MultiScalarMult(points []*Point, scalars []*Fq) {
	filippoPoints := make([]*filippo.Point, len(points))
	for i, pp := range points {
		filippoPoints[i] = &pp.V
	}
	filippoScalars := make([]*filippo.Scalar, len(scalars))
	for i, ss := range scalars {
		filippoScalars[i] = &ss.V
	}

	p.V.MultiScalarMult(filippoScalars, filippoPoints)
}
