package fields

func Pow[FP FieldElementPtrConstraint[FP, F], F any](result, base *F, exp []uint8) {
	var tmp, res F
	FP(&res).SetOne()

	for i := len(exp) - 1; i >= 0; i-- {
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>7)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>6)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>5)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>4)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>3)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>2)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>1)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).Select(uint64((exp[i]>>0)&1), &res, &tmp)
	}

	FP(result).Set(&res)
}
