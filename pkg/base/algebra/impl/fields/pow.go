package fields

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func Pow[FP impl.FiniteFieldElementPtr[FP, F], F any](result, base *F, exp []uint8) {
	var tmp, res F
	FP(&res).SetOne()

	for i := len(exp) - 1; i >= 0; i-- {
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>7)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>6)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>5)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>4)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>3)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>2)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>1)&1), &res, &tmp)
		FP(&res).Square(&res)
		FP(&tmp).Mul(&res, base)
		FP(&res).CondAssign(ct.Choice((exp[i]>>0)&1), &res, &tmp)
	}

	FP(result).Set(&res)
}
