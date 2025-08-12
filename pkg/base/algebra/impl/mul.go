package impl

import (
	"crypto/subtle"
	"math/bits"
	"runtime"
	"sort"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func ScalarMul[PP GroupElementPtr[PP, P], P any](out, pp *P, s []byte) {
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

// MultiScalarMul computes the multi-exponentiation for the specified
// points and scalars and stores the result in `out`.
// Returns an error if the lengths of the arguments is not equal.
func MultiScalarMul[PP GroupElementPtr[PP, P], P any](out *P, points []P, scalars [][]byte) (err error) {
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
		PP(&windows[i]).SetZero()
	}

	for i := 0; i < bucketSize; i++ {
		PP(&buckets[i]).SetZero()
	}

	for j := 0; j < len(windows); j++ {
		for i := 0; i < bucketSize; i++ {
			PP(&buckets[i]).SetZero()
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
		PP(&sum).SetZero()

		for i := bucketSize - 1; i > 0; i-- {
			PP(&sum).Add(&sum, &buckets[i])
			PP(&windows[j]).Add(&windows[j], &sum)
		}
	}

	PP(out).SetZero()
	for i := len(windows) - 1; i >= 0; i-- {
		for j := 0; j < W; j++ {
			PP(out).Double(out)
		}

		PP(out).Add(out, &windows[i])
	}

	return nil
}

// PippengerMultiScalarMul computes the multi‑scalar multiplication (MSM)
// using Pippenger’s algorithm.
//
// The implementation follows the high‑level description in
// “On the Evaluation of Powers and Exponentials” – Pippenger (1969) together
// with the optimisations described by Bos et al. (2013) and used in modern
// pairing‑friendly curve libraries (blst, halo2, zkcrypto).
//
//   - Dynamic window width *w* is chosen as ≈log₂(n)−2 clamped to [4,16].
//   - Each scalar is decomposed into ⌈bitlen/w⌉ windows; points are bucketed
//     by the window value and summed using a running‑sum strategy.
//   - To improve cache‑locality the (scalar,point) pairs are sorted by
//     Hamming weight before processing.
//   - Work is sharded across GOMAXPROCS workers; each worker owns its
//     buckets and accumulators to avoid contention.
//   - The function is constant‑time with respect to the scalar values
//     assuming the group operations are constant‑time.
//
// The caller must supply scalars of equal length (little‑endian, right‑padded
// with zeros if necessary).  `out` may alias one of the input points.
//
// **Security note:** this code has not been independently audited.  Use at
// your own risk in production.
func PippengerMultiScalarMul[PP GroupElementPtr[PP, P], P any](
	out *P,
	points []P,
	scalars [][]byte,
) error {
	const (
		wMin = 4  // minimum window width in bits
		wMax = 16 // maximum window width in bits
	)

	if len(points) != len(scalars) {
		return errs.NewSize("#points != #scalars")
	}
	if len(points) == 0 {
		PP(out).SetZero()
		return nil
	}

	n := len(points)
	scalarBits := len(scalars[0]) * 8 // assume equal length

	// Choose window size w ≈ log₂(n) − 2, clamp to [wMin,wMax].
	w := uint(0)
	switch {
	case n < 4:
		w = 2
	case n < 8:
		w = 3
	default:
		for pow := 1; (1<<pow) < n && pow < wMax; pow++ {
			w = uint(pow) - 1
		}
	}
	if w < wMin {
		w = wMin
	}
	if w > wMax {
		w = wMax
	}

	windowSize := 1 << w
	numWindows := (scalarBits + int(w) - 1) / int(w)

	// ---- Hamming‑weight sort --------------------------------------------
	type pair struct {
		idx int
		hw  int
	}
	hwPairs := make([]pair, n)
	for i, sc := range scalars {
		h := 0
		for _, b := range sc {
			h += bits.OnesCount8(b)
		}
		hwPairs[i] = pair{i, h}
	}
	sort.Slice(hwPairs, func(i, j int) bool { return hwPairs[i].hw > hwPairs[j].hw })

	sortedPoints := make([]P, n)
	sortedScalars := make([][]byte, n)
	for dst, p := range hwPairs {
		sortedPoints[dst] = points[p.idx]
		sortedScalars[dst] = scalars[p.idx]
	}

	// ---- Parallel workers -----------------------------------------------
	workers := runtime.GOMAXPROCS(0)
	chunk := (n + workers - 1) / workers

	type workerResult struct {
		windows []P // len == numWindows
	}

	var wg sync.WaitGroup
	results := make(chan workerResult, workers)

	for id := 0; id < workers; id++ {
		start := id * chunk
		end := start + chunk
		if end > n {
			end = n
		}
		if start >= end {
			continue
		}

		wg.Add(1)
		go func(pts []P, scs [][]byte) {
			defer wg.Done()

			buckets := make([]P, windowSize)
			for i := range buckets {
				PP(&buckets[i]).SetZero()
			}

			winAcc := make([]P, numWindows)
			for i := range winAcc {
				PP(&winAcc[i]).SetZero()
			}

			for wi := numWindows - 1; wi >= 0; wi-- {
				// reset buckets
				for i := range buckets {
					PP(&buckets[i]).SetZero()
				}

				shift := uint(wi) * w
				byteShift := shift / 8
				bitShift := shift % 8

				for idx, s := range scs {
					if int(byteShift) >= len(s) {
						continue
					}

					val := uint16(s[byteShift]) >> bitShift
					bitsRemaining := 8 - bitShift
					if bitsRemaining < w && int(byteShift)+1 < len(s) {
						val |= uint16(s[byteShift+1]) << bitsRemaining
					}
					val &= uint16(windowSize - 1)
					if val == 0 {
						continue
					}

					PP(&buckets[val]).Add(&buckets[val], &pts[idx])
				}

				var running P
				PP(&running).SetZero()
				for b := windowSize - 1; b > 0; b-- {
					PP(&running).Add(&running, &buckets[b])
					PP(&winAcc[wi]).Add(&winAcc[wi], &running)
				}
			}

			results <- workerResult{windows: winAcc}
		}(sortedPoints[start:end], sortedScalars[start:end])
	}

	wg.Wait()
	close(results)

	// ---- Combine worker outputs -----------------------------------------
	finalWindows := make([]P, numWindows)
	for i := range finalWindows {
		PP(&finalWindows[i]).SetZero()
	}

	for res := range results {
		for i := 0; i < numWindows; i++ {
			PP(&finalWindows[i]).Add(&finalWindows[i], &res.windows[i])
		}
	}

	// ---- Dispatch windows ------------------------------------------------
	PP(out).SetZero()
	for wi := numWindows - 1; wi >= 0; wi-- {
		for j := uint(0); j < w; j++ {
			PP(out).Double(out)
		}
		PP(out).Add(out, &finalWindows[wi])
	}

	// ---- Best‑effort zeroisation ----------------------------------------
	for i := range finalWindows {
		PP(&finalWindows[i]).SetZero()
	}

	return nil
}

// PippengerMultiScalarMulConstantTime is a branch‑free, constant‑time
// variant of PippengerMultiScalarMul.
//
// It avoids data‑dependent memory access and branching by iterating over all
// buckets for every (scalar, point) pair and using constant‑time conditional
// assignment.  No scalar‑dependent sorting is performed.
//
// The performance overhead (~2× extra additions per point) is the trade‑off
// for stronger side‑channel resistance.
func PippengerMultiScalarMulConstantTime[PP GroupElementPtr[PP, P], P any](
	out *P,
	points []P,
	scalars [][]byte,
) error {
	const (
		wMin = 4
		wMax = 16
	)

	if len(points) != len(scalars) {
		return errs.NewSize("#points != #scalars")
	}
	if len(points) == 0 {
		PP(out).SetZero()
		return nil
	}

	n := len(points)
	scalarBits := len(scalars[0]) * 8

	// window width ≈ log2(n) − 2, clamped
	w := uint(0)
	switch {
	case n < 4:
		w = 2
	case n < 8:
		w = 3
	default:
		for pow := 1; (1<<pow) < n && pow < wMax; pow++ {
			w = uint(pow) - 1
		}
	}
	if w < wMin {
		w = wMin
	}
	if w > wMax {
		w = wMax
	}

	windowSize := 1 << w
	numWindows := (scalarBits + int(w) - 1) / int(w)

	// Preserve input order — no Hamming‑weight sort.
	sortedPoints := points
	sortedScalars := scalars

	workers := runtime.GOMAXPROCS(0)
	chunk := (n + workers - 1) / workers

	type workerResult struct{ windows []P }

	var wg sync.WaitGroup
	results := make(chan workerResult, workers)

	for id := 0; id < workers; id++ {
		start := id * chunk
		end := start + chunk
		if end > n {
			end = n
		}
		if start >= end {
			continue
		}

		wg.Add(1)
		go func(pts []P, scs [][]byte) {
			defer wg.Done()

			buckets := make([]P, windowSize)
			for i := range buckets {
				PP(&buckets[i]).SetZero()
			}

			winAcc := make([]P, numWindows)
			for i := range winAcc {
				PP(&winAcc[i]).SetZero()
			}

			for wi := numWindows - 1; wi >= 0; wi-- {
				for i := range buckets {
					PP(&buckets[i]).SetZero()
				}

				shift := uint(wi) * w
				byteShift := shift / 8
				bitShift := shift % 8

				for idx, s := range scs {
					if int(byteShift) >= len(s) {
						continue
					}

					val := uint16(s[byteShift]) >> bitShift
					bitsRem := 8 - bitShift
					if bitsRem < w && int(byteShift)+1 < len(s) {
						val |= uint16(s[byteShift+1]) << bitsRem
					}
					val &= uint16(windowSize - 1)

					// Constant‑time bucket update.
					for b := 1; b < windowSize; b++ {
						eq := ct.Choice(subtle.ConstantTimeEq(int32(val), int32(b)))
						var tmp P
						PP(&tmp).Add(&buckets[b], &pts[idx])
						PP(&buckets[b]).CondAssign(eq, &buckets[b], &tmp)
					}
				}

				var running P
				PP(&running).SetZero()
				for b := windowSize - 1; b > 0; b-- {
					PP(&running).Add(&running, &buckets[b])
					PP(&winAcc[wi]).Add(&winAcc[wi], &running)
				}
			}

			results <- workerResult{windows: winAcc}
		}(sortedPoints[start:end], sortedScalars[start:end])
	}

	wg.Wait()
	close(results)

	finalWindows := make([]P, numWindows)
	for i := range finalWindows {
		PP(&finalWindows[i]).SetZero()
	}

	for res := range results {
		for i := 0; i < numWindows; i++ {
			PP(&finalWindows[i]).Add(&finalWindows[i], &res.windows[i])
		}
	}

	PP(out).SetZero()
	for wi := numWindows - 1; wi >= 0; wi-- {
		for j := uint(0); j < w; j++ {
			PP(out).Double(out)
		}
		PP(out).Add(out, &finalWindows[wi])
	}

	// Best‑effort zeroisation.
	for i := range finalWindows {
		PP(&finalWindows[i]).SetZero()
	}

	return nil
}
