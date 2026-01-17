package impl

import (
	"math/bits"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func ScalarMulLowLevel[PP GroupElementPtrLowLevel[PP, P], P any](out, pp *P, s []byte) {
	var precomputed [16]P

	PP(&precomputed[0]).SetZero()
	PP(&precomputed[1]).Set(pp)
	for i := 2; i < 16; i += 2 {
		PP(&precomputed[i]).Double(&precomputed[i/2])
		PP(&precomputed[i+1]).Add(&precomputed[i], pp)
	}

	var res P
	PP(&res).SetZero()
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

// MultiScalarMulLowLevel performs a Pippenger-style multi-scalar multiplication:
//
//	sum_i scalars[i] * points[i]
//
// using a fixed window size w.
//
// It assumes S.Bytes() is little-endian (LSB at index 0).
func MultiScalarMulLowLevel[PP GroupElementPtrLowLevel[PP, P], P any](
	out *P,
	points []*P,
	scalars [][]byte,
) {
	n := len(points)
	if n == 0 {
		panic("MultiScalarMul: no points")
	}
	if n != len(scalars) {
		panic("MultiScalarMul: number of points and scalars must be equal")
	}

	// Use naive method for small n.
	if n <= 7 {
		var acc P
		PP(&acc).SetZero()
		for i := range n {
			var term P
			ScalarMulLowLevel[PP](&term, points[i], scalars[i])
			PP(&acc).Add(&acc, &term)
		}
		PP(out).Set(&acc)
		return
	}

	// Precompute scalar bytes and max bit length.
	scalarBytes := make([][]byte, n)
	maxBits := 0
	for i, s := range scalars {
		scalarBytes[i] = s
		if bits := len(s) * 8; bits > maxBits {
			maxBits = bits
		}
	}
	if maxBits == 0 {
		// All scalars are zero.
		PP(out).SetZero()
		return
	}

	// Choose window size w.
	// A heuristic: w ≈ log2(n), but clamp to [2, 16].
	w := 0
	if n > 0 {
		w = bits.Len(uint(n)) // log2(n) rounded up
	}
	if w < 2 {
		w = 2
	}
	if w > 16 {
		w = 16
	}

	windowSize := 1 << w
	numWindows := (maxBits + w - 1) / w // ceil(maxBits / w)

	// Helper: get window of w bits starting at bit position `start` (LSB = bit 0).
	// Assumes little-endian byte order (LSB at index 0).
	getWindow := func(b []byte, start int) uint {
		if len(b) == 0 {
			return 0
		}
		var acc uint = 0
		for k := range w {
			bitIndex := start + k
			byteIndex := bitIndex / 8
			if byteIndex >= len(b) {
				break
			}
			shift := uint(bitIndex % 8)
			bit := (b[byteIndex] >> shift) & 1
			acc |= uint(bit) << uint(k)
		}
		return acc
	}

	var acc P
	PP(&acc).SetZero()
	for wIdx := numWindows - 1; wIdx >= 0; wIdx-- {
		for range w {
			PP(&acc).Add(&acc, &acc)
		}
		buckets := make([]PP, windowSize)
		for i := range buckets {
			var b P
			PP(&b).SetZero()
			buckets[i] = PP(&b)
		}
		startBit := wIdx * w
		for i := range n {
			win := getWindow(scalarBytes[i], startBit)
			if win == 0 {
				continue
			}
			buckets[win].Add(buckets[win], points[i])
		}

		// Summation by running sum from highest bucket down.
		// This gives: sum_{k=1}^{windowSize-1} k * bucket_k
		// with only ~windowSize additions.
		var running P
		PP(&running).SetZero()
		for k := windowSize - 1; k > 0; k-- {
			if isIdentity := buckets[k].IsZero(); isIdentity == ct.False {
				PP(&running).Add(&running, buckets[k])
			}
			PP(&acc).Add(&acc, &running)
		}
	}

	PP(out).Set(&acc)
}
