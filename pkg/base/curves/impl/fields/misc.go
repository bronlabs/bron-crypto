package fields

func IsNegative[FP PrimeFieldPtrConstraint[FP, F], F any](v *F) (neg uint64) {
	var vNeg F
	FP(&vNeg).Neg(v)
	return greaterLimbs(FP(v).Limbs(), FP(&vNeg).Limbs())
}

func IsOdd[FP PrimeFieldPtrConstraint[FP, F], F any](v *F) (odd uint64) {
	return uint64(FP(v).Bytes()[0] & 0b1)
}

func Degree[FP FiniteFieldPtrConstraint[FP, F], F any]() uint64 {
	return FP(nil).Degree()
}

func greaterLimbs(l, r []uint64) (gt uint64) {
	gt = 0
	lt := uint64(0)
	for i := len(l) - 1; i >= 0; i-- {
		gt |= greater(l[i], r[i]) & ^lt
		lt |= less(l[i], r[i]) & ^gt
	}
	return gt
}

func greater(x, y uint64) (gt uint64) {
	z := y - x
	return (z ^ ((x ^ y) & (x ^ z))) >> 63
}

func less(x, y uint64) (lt uint64) {
	return greater(y, x)
}
