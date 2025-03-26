package points

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func ScalarMul[FP fieldsImpl.FiniteField[FP], PP PointPtrConstraint[FP, PP, P], P any](out, pp *P, s []byte) {
	var precomputed [16]P

	PP(&precomputed[0]).SetIdentity()
	PP(&precomputed[1]).Set(pp)
	for i := 2; i < 16; i += 2 {
		PP(&precomputed[i]).Double(&precomputed[i/2])
		PP(&precomputed[i+1]).Add(&precomputed[i], pp)
	}

	var res P
	PP(&res).SetIdentity()
	for i := len(s) - 1; i >= 0; i-- {
		PP(&res).Double(&res)
		PP(&res).Double(&res)
		PP(&res).Double(&res)
		PP(&res).Double(&res)
		w := (s[i] >> 4) & 0b1111
		PP(&res).Add(&res, &precomputed[w])

		PP(&res).Double(&res)
		PP(&res).Double(&res)
		PP(&res).Double(&res)
		PP(&res).Double(&res)
		w = s[i] & 0b1111
		PP(&res).Add(&res, &precomputed[w])
	}

	PP(out).Set(&res)
}

// MultiScalarMul computes the multi-exponentiation for the specified
// points and scalars and stores the result in `out`.
// Returns an error if the lengths of the arguments is not equal.
func MultiScalarMul[FP fieldsImpl.FiniteField[FP], PP PointPtrConstraint[FP, PP, P], P any](out *P, points []P, scalars [][]byte) (err error) {
	const Upper = 256
	const W = 4
	const Windows = Upper / W // careful--use ceiling division in case this doesn't divide evenly
	if len(points) != len(scalars) {
		return errs.NewSize("#points != #scalars")
	}

	bucketSize := 1 << W
	windows := make([]P, Windows)
	buckets := make([]P, bucketSize)

	for i := range windows {
		PP(&windows[i]).SetIdentity()
	}

	for i := 0; i < bucketSize; i++ {
		PP(&buckets[i]).SetIdentity()
	}

	for j := 0; j < len(windows); j++ {
		for i := 0; i < bucketSize; i++ {
			PP(&buckets[i]).SetIdentity()
		}

		for i := 0; i < len(scalars); i++ {
			// j*W to get the nibble
			// >> 3 to convert to byte, / 8
			// (W * j & W) gets the nibble, mod W
			// 1 << W - 1 to get the offset
			index := scalars[i][j*W>>3] >> (W * j & W) & (1<<W - 1) // little-endian
			PP(&buckets[index]).Add(&buckets[index], &points[i])
		}

		var sum P
		PP(&sum).SetIdentity()

		for i := bucketSize - 1; i > 0; i-- {
			PP(&sum).Add(&sum, &buckets[i])
			PP(&windows[j]).Add(&windows[j], &sum)
		}
	}

	PP(out).SetIdentity()
	for i := len(windows) - 1; i >= 0; i-- {
		for j := 0; j < W; j++ {
			PP(out).Double(out)
		}

		PP(out).Add(out, &windows[i])
	}

	return nil
}
