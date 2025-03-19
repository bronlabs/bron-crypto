package fields

import (
	"io"
	"slices"
)

type CubicFieldExtensionArithmetic[BF FiniteFieldElement[BF]] interface {
	MulByCubicNonResidue(out BF, in BF)
	RootOfUnity(out BF)
	ProgenitorExponent() []uint8
	E() uint64
}

type CubicFieldExtensionImpl[BFP interface {
	*BF
	FiniteFieldElement[BFP]
}, A CubicFieldExtensionArithmetic[BFP], BF any] struct {
	U0 BF
	U1 BF
	U2 BF
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Set(v *CubicFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Set(&v.U0)
	BFP(&f.U1).Set(&v.U1)
	BFP(&f.U2).Set(&v.U2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) SetZero() {
	BFP(&f.U0).SetZero()
	BFP(&f.U1).SetZero()
	BFP(&f.U2).SetZero()
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) SetOne() {
	BFP(&f.U0).SetOne()
	BFP(&f.U1).SetZero()
	BFP(&f.U2).SetZero()
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) SetUniformBytes(data ...[]byte) (ok uint64) {
	componentsLen := len(data) / 3
	ok0 := BFP(&f.U0).SetUniformBytes(data[:componentsLen]...)
	ok1 := BFP(&f.U1).SetUniformBytes(data[componentsLen : 2*componentsLen]...)
	ok2 := BFP(&f.U2).SetUniformBytes(data[2*componentsLen:]...)
	return ok0 & ok1 & ok2
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) SetRandom(prng io.Reader) (ok uint64) {
	ok0 := BFP(&f.U0).SetRandom(prng)
	ok1 := BFP(&f.U1).SetRandom(prng)
	ok2 := BFP(&f.U2).SetRandom(prng)
	return ok0 & ok1 & ok2
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Select(choice uint64, z, nz *CubicFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Select(choice, &z.U0, &nz.U0)
	BFP(&f.U1).Select(choice, &z.U1, &nz.U1)
	BFP(&f.U2).Select(choice, &z.U2, &nz.U2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Add(lhs, rhs *CubicFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Add(&lhs.U0, &rhs.U0)
	BFP(&f.U1).Add(&lhs.U1, &rhs.U1)
	BFP(&f.U2).Add(&lhs.U2, &rhs.U2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Sub(lhs, rhs *CubicFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Sub(&lhs.U0, &rhs.U0)
	BFP(&f.U1).Sub(&lhs.U1, &rhs.U1)
	BFP(&f.U2).Sub(&lhs.U2, &rhs.U2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Neg(v *CubicFieldExtensionImpl[BFP, A, BF]) {
	BFP(&f.U0).Neg(&v.U0)
	BFP(&f.U1).Neg(&v.U1)
	BFP(&f.U2).Neg(&v.U2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Mul(lhs, rhs *CubicFieldExtensionImpl[BFP, A, BF]) {
	var arith A
	var v0, v1, v2 BF
	var a0PlusA1, a0PlusA2, a1PlusA2 BF
	var c0, c1, c2 BF

	// v0 = a0*b0, v1 = a1*b1, v2 = a2*b2
	BFP(&v0).Mul(&lhs.U0, &rhs.U0)
	BFP(&v1).Mul(&lhs.U1, &rhs.U1)
	BFP(&v2).Mul(&lhs.U2, &rhs.U2)
	BFP(&a0PlusA1).Add(&lhs.U0, &lhs.U1)
	BFP(&a0PlusA2).Add(&lhs.U0, &lhs.U2)
	BFP(&a1PlusA2).Add(&lhs.U1, &lhs.U2)

	BFP(&c2).Add(&rhs.U0, &rhs.U2)
	BFP(&c2).Mul(&c2, &a0PlusA2)
	BFP(&c2).Sub(&c2, &v0)
	BFP(&c2).Add(&c2, &v1)
	BFP(&c2).Sub(&c2, &v2)

	BFP(&c0).Add(&rhs.U1, &rhs.U2)
	BFP(&c0).Mul(&c0, &a1PlusA2)
	BFP(&c0).Sub(&c0, &v1)
	BFP(&c0).Sub(&c0, &v2)
	arith.MulByCubicNonResidue(&c0, &c0)
	BFP(&c0).Add(&c0, &v0)

	arith.MulByCubicNonResidue(&v2, &v2)
	BFP(&c1).Add(&rhs.U0, &rhs.U1)
	BFP(&c1).Mul(&c1, &a0PlusA1)
	BFP(&c1).Sub(&c1, &v0)
	BFP(&c1).Sub(&c1, &v1)
	BFP(&c1).Add(&c1, &v2)

	BFP(&f.U0).Set(&c0)
	BFP(&f.U1).Set(&c1)
	BFP(&f.U2).Set(&c2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Square(v *CubicFieldExtensionImpl[BFP, A, BF]) {
	var arith A
	var v0, v1, v2 BF
	var c0, c1, c2 BF

	BFP(&v0).Square(&v.U0)
	BFP(&v1).Square(&v.U1)
	BFP(&v2).Square(&v.U2)

	BFP(&c2).Add(&v.U0, &v.U2)
	BFP(&c2).Square(&c2)
	BFP(&c2).Sub(&c2, &v0)
	BFP(&c2).Add(&c2, &v1)
	BFP(&c2).Sub(&c2, &v2)

	BFP(&c0).Add(&v.U1, &v.U2)
	BFP(&c0).Square(&c0)
	BFP(&c0).Sub(&c0, &v1)
	BFP(&c0).Sub(&c0, &v2)
	arith.MulByCubicNonResidue(&c0, &c0)
	BFP(&c0).Add(&c0, &v0)

	BFP(&c1).Add(&v.U0, &v.U1)
	BFP(&c1).Square(&c1)
	BFP(&c1).Sub(&c1, &v0)
	BFP(&c1).Sub(&c1, &v1)
	arith.MulByCubicNonResidue(&v2, &v2)
	BFP(&c1).Add(&c1, &v2)

	BFP(&f.U0).Set(&c0)
	BFP(&f.U1).Set(&c1)
	BFP(&f.U2).Set(&c2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Inv(arg *CubicFieldExtensionImpl[BFP, A, BF]) (ok uint64) {
	var arith A
	var a, b, c, s, t BF

	// a' = a^2 - (b * c) * beta
	BFP(&a).Mul(&arg.U1, &arg.U2)
	arith.MulByCubicNonResidue(&a, &a)
	BFP(&t).Square(&arg.U0)
	BFP(&a).Sub(&t, &a)

	// b' = c^2 * beta - (a * b)
	BFP(&b).Square(&arg.U2)
	arith.MulByCubicNonResidue(&b, &b)
	BFP(&t).Mul(&arg.U0, &arg.U1)
	BFP(&b).Sub(&b, &t)

	// c' = b^2 - (a * c)
	BFP(&c).Square(&arg.U1)
	BFP(&t).Mul(&arg.U0, &arg.U2)
	BFP(&c).Sub(&c, &t)

	// t = ((b * c') + (c * b')) * beta + (a * a')
	BFP(&s).Mul(&arg.U1, &c)
	BFP(&t).Mul(&arg.U2, &b)
	BFP(&s).Add(&s, &t)
	arith.MulByCubicNonResidue(&s, &s)
	BFP(&t).Mul(&arg.U0, &a)
	BFP(&s).Add(&s, &t)
	ok = BFP(&t).Inv(&s)

	if ok == 1 {
		var sanityCheck BF
		BFP(&sanityCheck).Mul(&t, &s)
		if BFP(&sanityCheck).IsOne() != 1 {
			panic("sanity check failed")
		}
	}

	// c0 = a' * t^-1
	var c0, c1, c2 BF
	BFP(&c0).Mul(&a, &t)
	// c1 = b' * t^-1
	BFP(&c1).Mul(&b, &t)
	// c2 = c' * t^-1
	BFP(&c2).Mul(&c, &t)

	BFP(&f.U0).Select(ok, &f.U0, &c0)
	BFP(&f.U1).Select(ok, &f.U1, &c1)
	BFP(&f.U2).Select(ok, &f.U2, &c2)

	//if ok == 1 {
	//	var sanityCheck CubicFieldExtensionImpl[BFPtr, A, BF]
	//	sanityCheck.Mul(f, arg)
	//	if sanityCheck.IsOne() != 1 {
	//		panic("sanity check failed")
	//	}
	//}

	return ok
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Div(lhs, rhs *CubicFieldExtensionImpl[BFP, A, BF]) (ok uint64) {
	var rhsInv, result CubicFieldExtensionImpl[BFP, A, BF]
	ok = rhsInv.Inv(rhs)
	result.Mul(lhs, &rhsInv)

	f.Select(ok, f, &result)
	return ok
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Sqrt(v *CubicFieldExtensionImpl[BFP, A, BF]) (ok uint64) {
	var arith A
	var rootOfUnity CubicFieldExtensionImpl[BFP, A, BF]
	rootOfUnity.SetZero()
	arith.RootOfUnity(&rootOfUnity.U0)

	ok = TonelliShanks(f, v, &rootOfUnity, arith.E(), arith.ProgenitorExponent())
	return ok
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) IsNonZero() uint64 {
	return BFP(&f.U0).IsNonZero() | BFP(&f.U1).IsNonZero() | BFP(&f.U2).IsNonZero()
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) IsZero() uint64 {
	return BFP(&f.U0).IsZero() & BFP(&f.U1).IsZero() & BFP(&f.U2).IsZero()
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) IsOne() uint64 {
	return BFP(&f.U0).IsOne() & BFP(&f.U1).IsZero() & BFP(&f.U2).IsZero()
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) Equals(rhs *CubicFieldExtensionImpl[BFP, A, BF]) uint64 {
	return BFP(&f.U0).Equals(&rhs.U0) & BFP(&f.U1).Equals(&rhs.U1) & BFP(&f.U2).Equals(&rhs.U2)
}

func (f *CubicFieldExtensionImpl[BFP, A, BF]) ComponentsBytes() [][]byte {
	return slices.Concat(BFP(&f.U0).ComponentsBytes(), BFP(&f.U1).ComponentsBytes(), BFP(&f.U2).ComponentsBytes())
}

func (*CubicFieldExtensionImpl[BFP, A, BF]) ToHex() string {
	panic("implement me")
}

func (*CubicFieldExtensionImpl[BFP, A, BF]) Degree() uint64 {
	return BFP(nil).Degree() * 3
}
