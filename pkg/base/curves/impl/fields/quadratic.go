package fields

import (
	"io"
	"slices"
)

type QuadraticFieldExtensionArith[BFP FiniteFieldPtr[BFP]] interface {
	MulByQuadraticNonResidue(out BFP, in BFP)
}

type QuadraticFieldExtensionImpl[BFP FiniteFieldPtrConstraint[BFP, BF], A QuadraticFieldExtensionArith[BFP], BF any] struct {
	U0 BF
	U1 BF
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Set(v *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Set(&v.U0)
	BFP(&f.U1).Set(&v.U1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) SetZero() {
	BFP(&f.U0).SetZero()
	BFP(&f.U1).SetZero()
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) SetOne() {
	BFP(&f.U0).SetOne()
	BFP(&f.U1).SetZero()
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) SetUniformBytes(componentsData ...[]byte) (ok uint64) {
	componentsDataLen := len(componentsData) / 2
	l := componentsData[:componentsDataLen]
	h := componentsData[componentsDataLen:]
	okl := BFP(&f.U0).SetUniformBytes(l...)
	okh := BFP(&f.U1).SetUniformBytes(h...)
	return okl & okh
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) SetRandom(prng io.Reader) (ok uint64) {
	ok0 := BFP(&f.U0).SetRandom(prng)
	ok1 := BFP(&f.U1).SetRandom(prng)
	return ok0 & ok1
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Select(choice uint64, z, nz *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Select(choice, &z.U0, &nz.U0)
	BFP(&f.U1).Select(choice, &z.U1, &nz.U1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Add(lhs, rhs *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Add(&lhs.U0, &rhs.U0)
	BFP(&f.U1).Add(&lhs.U1, &rhs.U1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Sub(lhs, rhs *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Sub(&lhs.U0, &rhs.U0)
	BFP(&f.U1).Sub(&lhs.U1, &rhs.U1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Neg(v *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Neg(&v.U0)
	BFP(&f.U1).Neg(&v.U1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Mul(lhs, rhs *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	var arith A
	var v0, v1 BF
	var c0, c1 BF

	// v0 = a0*b0, v1 = b1*v1
	BFP(&v0).Mul(&lhs.U0, &rhs.U0)
	BFP(&v1).Mul(&lhs.U1, &rhs.U1)

	// c0 = v0 + beta * v1
	arith.MulByQuadraticNonResidue(&c0, &v1)
	BFP(&c0).Add(&c0, &v0)

	// c1 = (a0 + a1)(b0 + b1) - v0 - v1
	var a0PlusA1 BF
	BFP(&a0PlusA1).Add(&lhs.U0, &lhs.U1)
	BFP(&c1).Add(&rhs.U0, &rhs.U1)
	BFP(&c1).Mul(&c1, &a0PlusA1)
	BFP(&c1).Sub(&c1, &v0)
	BFP(&c1).Sub(&c1, &v1)

	BFP(&f.U0).Set(&c0)
	BFP(&f.U1).Set(&c1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Square(v *QuadraticFieldExtensionImpl[BFP, A, BF]) {
	var arith A
	var v0 BF
	var c0, c1 BF
	BFP(&v0).Mul(&v.U0, &v.U1)

	// c1 = 2v0
	BFP(&c1).Add(&v0, &v0)

	// c0 = (a0 + a1)(a0 + beta * a1) - v0 - beta * v0
	var a0PlusA1 BF
	BFP(&a0PlusA1).Add(&v.U0, &v.U1)
	arith.MulByQuadraticNonResidue(&c0, &v.U1)
	BFP(&c0).Add(&c0, &v.U0)
	BFP(&c0).Mul(&c0, &a0PlusA1)
	BFP(&c0).Sub(&c0, &v0)
	arith.MulByQuadraticNonResidue(&v0, &v0)
	BFP(&c0).Sub(&c0, &v0)

	BFP(&f.U0).Set(&c0)
	BFP(&f.U1).Set(&c1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Inv(v *QuadraticFieldExtensionImpl[BFP, A, BF]) (ok uint64) {
	var arith A
	var betaA1Squared BF
	BFP(&betaA1Squared).Square(&v.U1)
	arith.MulByQuadraticNonResidue(&betaA1Squared, &betaA1Squared)

	var nom, den BF
	BFP(&nom).Square(&v.U0)
	BFP(&nom).Sub(&nom, &betaA1Squared)
	ok = BFP(&den).Inv(&nom)

	if ok == 1 {
		var sanityCheck BF
		BFP(&sanityCheck).Mul(&den, &nom)
		if BFP(&sanityCheck).IsOne() != 1 {
			panic("sanity check failed")
		}
	}

	var c0, c1 BF
	BFP(&c0).Mul(&v.U0, &den)
	BFP(&c1).Neg(&v.U1)
	BFP(&c1).Mul(&c1, &den)

	if ok == 1 {
		var sanityCheck QuadraticFieldExtensionImpl[BFP, A, BF]
		BFP(&sanityCheck.U0).Set(&c0)
		BFP(&sanityCheck.U1).Set(&c1)
		sanityCheck.Mul(&sanityCheck, v)
		if sanityCheck.IsOne() != 1 {
			panic("sanity check failed")
		}
	}

	BFP(&f.U0).Select(ok, &f.U0, &c0)
	BFP(&f.U1).Select(ok, &f.U1, &c1)

	return ok
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Div(lhs, rhs *QuadraticFieldExtensionImpl[BFP, A, BF]) (ok uint64) {
	var result, rhsInv QuadraticFieldExtensionImpl[BFP, A, BF]
	ok = rhsInv.Inv(rhs)
	result.Mul(lhs, &rhsInv)

	f.Select(ok, f, &result)
	return ok
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Sqrt(v *QuadraticFieldExtensionImpl[BFP, A, BF]) (ok uint64) {
	var arith A
	var betaA1Square, half, pos, neg, com BF

	BFP(&half).SetOne()
	BFP(&half).Add(&half, &half)
	ok1 := BFP(&half).Inv(&half)

	BFP(&betaA1Square).Square(&v.U1)
	arith.MulByQuadraticNonResidue(&betaA1Square, &betaA1Square)

	BFP(&pos).Square(&v.U0)
	BFP(&pos).Sub(&pos, &betaA1Square)
	ok2 := BFP(&pos).Sqrt(&pos)
	BFP(&neg).Set(&pos)
	BFP(&pos).Add(&v.U0, &pos)
	BFP(&neg).Sub(&v.U0, &neg)
	BFP(&pos).Mul(&pos, &half)
	BFP(&neg).Mul(&neg, &half)
	ok3p := BFP(&pos).Sqrt(&pos)
	ok3n := BFP(&neg).Sqrt(&neg)

	okp := ok1 & ok2 & ok3p
	okn := ok1 & ok2 & ok3n

	BFP(&com).Select(okp, &com, &pos)
	BFP(&com).Select(okn, &com, &neg)
	BFP(&com).Add(&com, &com)
	ok4 := BFP(&com).Inv(&com)
	BFP(&com).Mul(&com, &v.U1)

	BFP(&f.U0).Select(okp&ok4, &f.U0, &pos)
	BFP(&f.U0).Select(okn&ok4, &f.U0, &neg)
	BFP(&f.U1).Select((okp|okn)&ok4, &f.U0, &com)

	return (okp | okn) & ok4
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) IsNonZero() uint64 {
	return BFP(&f.U0).IsNonZero() | BFP(&f.U1).IsNonZero()
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) IsZero() uint64 {
	return BFP(&f.U0).IsZero() & BFP(&f.U1).IsZero()
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) IsOne() uint64 {
	return BFP(&f.U0).IsOne() & BFP(&f.U1).IsZero()
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) Equals(rhs *QuadraticFieldExtensionImpl[BFP, A, BF]) uint64 {
	return BFP(&f.U0).Equals(&rhs.U0) & BFP(&f.U1).Equals(&rhs.U1)
}

func (f *QuadraticFieldExtensionImpl[BFP, A, BF]) ComponentsBytes() [][]byte {
	return slices.Concat(BFP(&f.U0).ComponentsBytes(), BFP(&f.U1).ComponentsBytes())
}

func (*QuadraticFieldExtensionImpl[BFP, A, BF]) Degree() uint64 {
	return BFP(nil).Degree() * 2
}
