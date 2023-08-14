package curves

import (
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// Curve represents a named elliptic curve with a scalar field and point group.
type Curve interface {
	Scalar() Scalar
	Point() Point

	Name() string
	Generator() Point
	ScalarBaseMult(sc Scalar) Point
	MultiScalarMult(scalars []Scalar, points []Point) (Point, error)
	DeriveAffine(x Element) (Point, Point, error)
}

type PairingCurve interface {
	Name() string

	G1() Curve
	G2() Curve
	Gt() Scalar

	Pairing(pG1 PairingPoint, pG2 PairingPoint) Scalar
	MultiPairing(...PairingPoint) Scalar
}

type WeierstrassCurve interface {
	Curve
	WeierstrassPoint
}

// PippengerMultiScalarMult implements a version of Pippenger's algorithm.
//
// The algorithm works as follows:
//
// Let `n` be a number of point-scalar pairs.
// Let `w` be a window of bits (6..8, chosen based on `n`, see cost factor).
//
//  1. Prepare `2^(w-1) - 1` buckets with indices `[1..2^(w-1))` initialised with identity points.
//     Bucket 0 is not needed as it would contain points multiplied by 0.
//  2. Convert scalars to a radix-`2^w` representation with signed digits in `[-2^w/2, 2^w/2]`.
//     Note: only the last digit may equal `2^w/2`.
//  3. Starting with the last window, for each point `i=[0..n)` add it to a bucket indexed by
//     the point's scalar's value in the window.
//  4. Once all points in a window are sorted into buckets, add buckets by multiplying each
//     by their index. Efficient way of doing it is to start with the last bucket and compute two sums:
//     intermediate sum from the last to the first, and the full sum made of all intermediate sums.
//  5. Shift the resulting sum of buckets by `w` bits by using `w` doublings.
//  6. Add to the return value.
//  7. Repeat the loop.
//
// Approximate cost w/o wNAF optimizations (A = addition, D = doubling):
//
// ```ascii
// cost = (n*A + 2*(2^w/2)*A + w*D + A)*256/w
//
//	      |          |       |     |   |
//	      |          |       |     |   looping over 256/w windows
//	      |          |       |     adding to the result
//	sorting points   |       shifting the sum by w bits (to the next window, starting from last window)
//	one by one       |
//	into buckets     adding/subtracting all buckets
//	                 multiplied by their indexes
//	                 using a sum of intermediate sums
//
// ```
//
// For large `n`, dominant factor is (n*256/w) additions.
// However, if `w` is too big and `n` is not too big, then `(2^w/2)*A` could dominate.
// Therefore, the optimal choice of `w` grows slowly as `n` grows.
//
// # For constant time we use a fixed window of 6
//
// This algorithm is adapted from section 4 of <https://eprint.iacr.org/2012/549.pdf>.
// and https://cacr.uwaterloo.ca/techreports/2010/cacr2010-26.pdf
func PippengerMultiScalarMult(points []Point, scalars []*big.Int) (Point, error) {
	if len(points) != len(scalars) {
		return nil, errs.NewIncorrectCount("point and scalar arrays lengths mismatch")
	}

	const w = 6

	bucketSize := (1 << w) - 1
	windows := make([]Point, 255/w+1)
	for i := range windows {
		windows[i] = points[0].Identity()
	}
	bucket := make([]Point, bucketSize)

	for j := 0; j < len(windows); j++ {
		for i := 0; i < bucketSize; i++ {
			bucket[i] = points[0].Identity()
		}

		for i := 0; i < len(scalars); i++ {
			index := bucketSize & int(new(big.Int).Rsh(scalars[i], uint(w*j)).Int64())
			if index != 0 {
				bucket[index-1] = bucket[index-1].Add(points[i])
			}
		}

		acc, sum := windows[j].Identity(), windows[j].Identity()

		for i := bucketSize - 1; i >= 0; i-- {
			sum = sum.Add(bucket[i])
			acc = acc.Add(sum)
		}
		windows[j] = acc
	}

	acc := windows[0].Identity()
	for i := len(windows) - 1; i >= 0; i-- {
		for j := 0; j < w; j++ {
			acc = acc.Double()
		}
		acc = acc.Add(windows[i])
	}
	return acc, nil
}
