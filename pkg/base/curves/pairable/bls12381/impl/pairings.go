package impl

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
)

const coefficientsG2 = 68

type Engine struct {
	pairs []pair
}

type pair struct {
	g1 G1Point
	g2 G2Point
}

type g2Prepared struct {
	identity     ct.Bool
	coefficients []coefficients
}

type coefficients struct {
	a, b, c Fp2
}

func (c *coefficients) Select(choice ct.Choice, arg0, arg1 *coefficients) *coefficients {
	c.a.Select(choice, &arg0.a, &arg1.a)
	c.b.Select(choice, &arg0.b, &arg1.b)
	c.c.Select(choice, &arg0.c, &arg1.c)
	return c
}

// AddPair adds a pair of points to be paired.
func (e *Engine) AddPair(g1 *G1Point, g2 *G2Point) *Engine {
	var p pair
	if g1.IsZero()|g2.IsZero() == 0 {
		affinize(&p.g1, g1)
		affinize(&p.g2, g2)
		e.pairs = append(e.pairs, p)
	}
	return e
}

// AddPairInvG1 adds a pair of points to be paired. G1 point is negated.
func (e *Engine) AddPairInvG1(g1 *G1Point, g2 *G2Point) *Engine {
	var p G1Point
	p.Neg(g1)
	return e.AddPair(&p, g2)
}

// AddPairInvG2 adds a pair of points to be paired. G2 point is negated.
func (e *Engine) AddPairInvG2(g1 *G1Point, g2 *G2Point) *Engine {
	var p G2Point
	p.Neg(g2)
	return e.AddPair(g1, &p)
}

func (e *Engine) Reset() *Engine {
	e.pairs = []pair{}
	return e
}

func (e *Engine) Check() bool {
	return e.pairing().IsOne() == 1
}

func (e *Engine) Result() *Fp12 {
	return e.pairing()
}

func (e *Engine) pairing() *Fp12 {
	f := new(Gt)
	f.SetOne()
	if len(e.pairs) == 0 {
		return &f.Fp12
	}
	coeffs := e.computeCoeffs()
	e.millerLoop(&f.Fp12, coeffs)

	f.FinalExponentiation(f)
	return &f.Fp12
}

func (e *Engine) millerLoop(f *Fp12, coeffs []g2Prepared) {
	newF := new(Fp12)
	newF.SetZero()
	found := uint64(0)
	cIdx := 0
	for i := 63; i >= 0; i-- {
		x := ((X >> 1) >> i) & 1
		if found == 0 {
			found |= x
			continue
		}

		// doubling
		for j, terms := range coeffs {
			identity := e.pairs[j].g1.IsZero() | ct.Bool(terms.identity)
			newF.Set(f)
			ell(newF, &terms.coefficients[cIdx], &e.pairs[j].g1)
			f.Select(identity, newF, f)
		}
		cIdx++

		if x == 1 {
			// adding
			for j, terms := range coeffs {
				identity := e.pairs[j].g1.IsZero() | ct.Bool(terms.identity)
				newF.Set(f)
				ell(newF, &terms.coefficients[cIdx], &e.pairs[j].g1)
				f.Select(identity, newF, f)
			}
			cIdx++
		}
		f.Square(f)
	}
	for j, terms := range coeffs {
		identity := e.pairs[j].g1.IsZero() | ct.Bool(terms.identity)
		newF.Set(f)
		ell(newF, &terms.coefficients[cIdx], &e.pairs[j].g1)
		f.Select(identity, newF, f)
	}
	Conjugate(f, f)
}

func (e *Engine) computeCoeffs() []g2Prepared {
	coeffs := make([]g2Prepared, len(e.pairs))
	for i := 0; i < len(e.pairs); i++ {
		p := e.pairs[i]
		identity := p.g2.IsZero()
		q := new(G2Point)
		q.SetGenerator()
		q.Select(identity, &p.g2, q)
		c := new(G2Point)
		c.Set(q)
		cfs := make([]coefficients, coefficientsG2)
		found := 0
		k := 0

		for j := 63; j >= 0; j-- {
			x := int(((X >> 1) >> j) & 1)
			if found == 0 {
				found |= x
				continue
			}
			cfs[k] = doublingStep(c)
			k++

			if x == 1 {
				cfs[k] = additionStep(c, q)
				k++
			}
		}
		cfs[k] = doublingStep(c)
		coeffs[i] = g2Prepared{
			coefficients: cfs, identity: identity,
		}
	}
	return coeffs
}

func ell(f *Fp12, coeffs *coefficients, p *G1Point) {
	var x, y Fp2
	x.U0.Mul(&coeffs.a.U0, &p.Y)
	x.U1.Mul(&coeffs.a.U1, &p.Y)
	y.U0.Mul(&coeffs.b.U0, &p.X)
	y.U1.Mul(&coeffs.b.U1, &p.X)
	mulByABD(f, f, &coeffs.c, &y, &x)
}

func doublingStep(p *G2Point) coefficients {
	// Adaptation of Algorithm 26, https://eprint.iacr.org/2010/354.pdf
	var t0, t1, t2, t3, t4, t5, t6, zsqr Fp2
	t0.Square(&p.X)
	t1.Square(&p.Y)
	t2.Square(&t1)
	t3.Add(&t1, &p.X)
	t3.Square(&t3)
	t3.Sub(&t3, &t0)
	t3.Sub(&t3, &t2)
	t3.Add(&t3, &t3)
	t4.Add(&t0, &t0)
	t4.Add(&t4, &t0)
	t6.Add(&p.X, &t4)
	t5.Square(&t4)
	zsqr.Square(&p.Z)
	p.X.Sub(&t5, &t3)
	p.X.Sub(&p.X, &t3)
	p.Z.Add(&p.Z, &p.Y)
	p.Z.Square(&p.Z)
	p.Z.Sub(&p.Z, &t1)
	p.Z.Sub(&p.Z, &zsqr)
	p.Y.Sub(&t3, &p.X)
	p.Y.Mul(&p.Y, &t4)
	t2.Add(&t2, &t2)
	t2.Add(&t2, &t2)
	t2.Add(&t2, &t2)
	p.Y.Sub(&p.Y, &t2)
	t3.Mul(&t4, &zsqr)
	t3.Add(&t3, &t3)
	t3.Neg(&t3)
	t6.Square(&t6)
	t6.Sub(&t6, &t0)
	t6.Sub(&t6, &t5)
	t1.Add(&t1, &t1)
	t1.Add(&t1, &t1)
	t6.Sub(&t6, &t1)
	t0.Mul(&p.Z, &zsqr)
	t0.Add(&t0, &t0)

	return coefficients{
		a: t0, b: t3, c: t6,
	}
}

func additionStep(r, q *G2Point) coefficients {
	// Adaptation of Algorithm 27, https://eprint.iacr.org/2010/354.pdf
	var zsqr, ysqr Fp2
	var t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10 Fp2
	zsqr.Square(&r.Z)
	ysqr.Square(&q.Y)
	t0.Mul(&zsqr, &q.X)
	t1.Add(&q.Y, &r.Z)
	t1.Square(&t1)
	t1.Sub(&t1, &ysqr)
	t1.Sub(&t1, &zsqr)
	t1.Mul(&t1, &zsqr)
	t2.Sub(&t0, &r.X)
	t3.Square(&t2)
	t4.Add(&t3, &t3)
	t4.Add(&t4, &t4)
	t5.Mul(&t4, &t2)
	t6.Sub(&t1, &r.Y)
	t6.Sub(&t6, &r.Y)
	t9.Mul(&t6, &q.X)
	t7.Mul(&t4, &r.X)
	r.X.Square(&t6)
	r.X.Sub(&r.X, &t5)
	r.X.Sub(&r.X, &t7)
	r.X.Sub(&r.X, &t7)
	r.Z.Add(&r.Z, &t2)
	r.Z.Square(&r.Z)
	r.Z.Sub(&r.Z, &zsqr)
	r.Z.Sub(&r.Z, &t3)
	t10.Add(&q.Y, &r.Z)
	t8.Sub(&t7, &r.X)
	t8.Mul(&t8, &t6)
	t0.Mul(&r.Y, &t5)
	t0.Add(&t0, &t0)
	r.Y.Sub(&t8, &t0)
	t10.Square(&t10)
	t10.Sub(&t10, &ysqr)
	zsqr.Square(&r.Z)
	t10.Sub(&t10, &zsqr)
	t9.Add(&t9, &t9)
	t9.Sub(&t9, &t10)
	t10.Add(&r.Z, &r.Z)
	t6.Neg(&t6)
	t1.Add(&t6, &t6)

	return coefficients{
		a: t10, b: t1, c: t9,
	}
}

// mulByABD computes arg * a * b * c.
func mulByABD(f, arg *Fp12, a, b, d *Fp2) {
	var params fp12Params
	var aa, bb, aTick, bTick Fp6
	var bd Fp2

	mulByAB(&aa, &arg.U0, a, b)
	mulByB(&bb, &arg.U1, d)
	bd.Add(b, d)

	bTick.Add(&arg.U0, &arg.U1)
	mulByAB(&bTick, &bTick, a, &bd)
	bTick.Sub(&bTick, &aa)
	bTick.Sub(&bTick, &bb)

	params.MulByQuadraticNonResidue(&aTick, &bb)
	aTick.Add(&aTick, &aa)

	f.U0.Set(&aTick)
	f.U1.Set(&bTick)
}

// MulByAB scales this field by scalars in the A and B coefficients.
func mulByAB(f, arg *Fp6, a, b *Fp2) {
	var params fp6Params
	var aA, bB, t1, t2, t3 Fp2

	aA.Mul(&arg.U0, a)
	bB.Mul(&arg.U1, b)

	t1.Add(&arg.U1, &arg.U2)
	t1.Mul(&t1, b)
	t1.Sub(&t1, &bB)
	params.MulByCubicNonResidue(&t1, &t1)
	t1.Add(&t1, &aA)

	t2.Add(a, b)
	t3.Add(&arg.U0, &arg.U1)
	t2.Mul(&t2, &t3)
	t2.Sub(&t2, &aA)
	t2.Sub(&t2, &bB)

	t3.Add(&arg.U0, &arg.U2)
	t3.Mul(&t3, a)
	t3.Sub(&t3, &aA)
	t3.Add(&t3, &bB)

	f.U0.Set(&t1)
	f.U1.Set(&t2)
	f.U2.Set(&t3)
}

// MulByB scales this field by a scalar in the B coefficient.
func mulByB(f, arg *Fp6, b *Fp2) {
	var params fp6Params
	var bB, t1, t2 Fp2

	bB.Mul(&arg.U1, b)
	// (b + c) * arg2 - bB
	t1.Add(&arg.U1, &arg.U2)
	t1.Mul(&t1, b)
	t1.Sub(&t1, &bB)
	params.MulByCubicNonResidue(&t1, &t1)

	t2.Add(&arg.U0, &arg.U1)
	t2.Mul(&t2, b)
	t2.Sub(&t2, &bB)

	f.U0.Set(&t1)
	f.U1.Set(&t2)
	f.U2.Set(&bB)
}

func affinize[FP fieldsImpl.FiniteFieldElementPtr[FP, F], C pointsImpl.ShortWeierstrassCurveParams[FP], H h2c.HasherParams, M h2c.PointMapper[FP], F any](out, in *pointsImpl.ShortWeierstrassPointImpl[FP, C, H, M, F]) {
	var x, y, zInv F
	FP(&zInv).Inv(&in.Z)
	FP(&x).Mul(&in.X, &zInv)
	FP(&y).Mul(&in.Y, &zInv)

	FP(&out.X).Set(&x)
	FP(&out.Y).Set(&y)
	FP(&out.Z).SetOne()
}
