package fields

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func TonelliShanks[FP impl.FiniteFieldElementPtr[FP, F], F any](out, x, ethRootOfUnity *F, e uint64, progenitorExp []uint8) (ok ct.Bool) {
	var y, s, t, z F

	Pow[FP](&y, x, progenitorExp)
	FP(&s).Mul(&y, x)
	FP(&t).Mul(&s, &y)
	FP(&z).Set(ethRootOfUnity)

	for k := e; k > 1; k-- {
		var b F
		FP(&b).Set(&t)
		for i := uint64(1); i < k-1; i++ {
			FP(&b).Square(&b)
		}
		var sz, tz F
		FP(&sz).Mul(&s, &z)
		FP(&s).Select(FP(&b).IsOne(), &sz, &s)
		FP(&z).Square(&z)
		FP(&tz).Mul(&t, &z)
		FP(&t).Select(FP(&b).IsOne(), &tz, &t)
	}

	var ss F
	FP(&ss).Square(&s)
	ok = FP(x).Equal(&ss)
	FP(out).Select(ok, out, &s)
	return ok
}
