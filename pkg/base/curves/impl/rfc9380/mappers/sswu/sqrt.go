package sswu

import (
	"encoding/binary"

	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// SqrtRatio computes sqrt(u/v) using constant-time steps from RFC 9380.
func SqrtRatio[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any](yOut *F, c1 uint64, c3 []uint8, c4, c5 uint64, c6, c7, u, v *F) (ok ct.Bool) {
	var one, tv1, tv2, tv3, tv4, tv5 F
	FP(&one).SetOne()

	//  1. tv1 = c6
	FP(&tv1).Set(c6)
	//  2. tv2 = v^c4
	fieldsImpl.Pow[FP](&tv2, v, binary.LittleEndian.AppendUint64(nil, c4))
	//  3. tv3 = tv2^2
	FP(&tv3).Square(&tv2)
	//  4. tv3 = tv3 * v
	FP(&tv3).Mul(&tv3, v)
	//  5. tv5 = u * tv3
	FP(&tv5).Mul(u, &tv3)
	//  6. tv5 = tv5^c3
	fieldsImpl.Pow[FP](&tv5, &tv5, c3)
	//  7. tv5 = tv5 * tv2
	FP(&tv5).Mul(&tv5, &tv2)
	//  8. tv2 = tv5 * v
	FP(&tv2).Mul(&tv5, v)
	//  9. tv3 = tv5 * u
	FP(&tv3).Mul(&tv5, u)
	// 10. tv4 = tv3 * tv2
	FP(&tv4).Mul(&tv3, &tv2)
	// 11. tv5 = tv4^c5
	fieldsImpl.Pow[FP](&tv5, &tv4, binary.LittleEndian.AppendUint64(nil, c5))
	// 12. isQR = tv5 == 1
	isQr := FP(&tv5).IsOne()
	// 13. tv2 = tv3 * c7
	FP(&tv2).Mul(&tv3, c7)
	// 14. tv5 = tv4 * tv1
	FP(&tv5).Mul(&tv4, &tv1)
	// 15. tv3 = CMOV(tv2, tv3, isQR)
	FP(&tv3).Select(isQr, &tv2, &tv3)
	// 16. tv4 = CMOV(tv5, tv4, isQR)
	FP(&tv4).Select(isQr, &tv5, &tv4)
	// 17. for i in (c1, c1 - 1, ..., 2):
	for i := c1; i >= 2; i-- {
		// 18. tv5 = i - 2
		tv5i := i - 2
		// 19. tv5 = 2 ^ tv5
		tv5i = 1 << tv5i
		// 20. tv5 = tv4 ^ tv5
		fieldsImpl.Pow[FP](&tv5, &tv4, binary.LittleEndian.AppendUint64(nil, tv5i))
		// 21. e1 = tv5 == 1
		e1 := FP(&tv5).IsOne()
		// 22. tv2 = tv3 * tv1
		FP(&tv2).Mul(&tv3, &tv1)
		// 23. tv1 = tv1 * tv1
		FP(&tv1).Square(&tv1)
		// 24. tv5 = tv4 * tv1
		FP(&tv5).Mul(&tv4, &tv1)
		// 25. tv3 = CMOV(tv2, tv3, e1)
		FP(&tv3).Select(e1, &tv2, &tv3)
		// 26. tv4 = CMOV(tv5, tv4, e1)
		FP(&tv4).Select(e1, &tv5, &tv4)
	}
	// 27. return (isQR, tv3)
	FP(yOut).Set(&tv3)
	return isQr
}

// SqrtRatio3Mod4 computes sqrt(u/v) for fields with p mod 4 == 3.
func SqrtRatio3Mod4[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any](yOut *F, c1 []uint8, c2, u, v *F) (ok ct.Bool) {
	var tv1, tv2, tv3, y1, y2 F

	//  1. tv1 = v^2
	FP(&tv1).Square(v)
	//  2. tv2 = u * v
	FP(&tv2).Mul(u, v)
	//  3. tv1 = tv1 * tv2
	FP(&tv1).Mul(&tv1, &tv2)
	//  4. y1 = tv1^c1
	fieldsImpl.Pow[FP](&y1, &tv1, c1)
	//  5. y1 = y1 * tv2
	FP(&y1).Mul(&y1, &tv2)
	//  6. y2 = y1 * c2
	FP(&y2).Mul(&y1, c2)
	//  7. tv3 = y1^2
	FP(&tv3).Square(&y1)
	//  8. tv3 = tv3 * v
	FP(&tv3).Mul(&tv3, v)
	//  9. isQR = tv3 == u
	isQR := FP(u).Equal(&tv3)
	// 10. y = CMOV(y2, y1, isQR)
	FP(yOut).Select(isQR, &y2, &y1)
	// 11. return (isQR, y)
	return isQR
}
