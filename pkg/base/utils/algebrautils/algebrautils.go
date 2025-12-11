package algebrautils

import (
	"io"
	"math/bits"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

// RandomNonIdentity samples a random element from the given finite monoid that is not the identity element.
func RandomNonIdentity[M interface {
	algebra.FiniteStructure[E]
	algebra.Monoid[E]
}, E algebra.MonoidElement[E]](m M, prng io.Reader) (E, error) {
	validationErrors := []error{}
	if utils.IsNil(m) {
		validationErrors = append(validationErrors, ErrArgumentIsNil.WithMessage("monoid"))
	}
	if prng == nil {
		validationErrors = append(validationErrors, ErrArgumentIsNil.WithMessage("prng"))
	}
	if len(validationErrors) > 0 {
		return *new(E), errs2.Join(validationErrors...)
	}
	var err error
	out := m.OpIdentity()
	for out.IsOpIdentity() {
		out, err = m.Random(prng)
		if err != nil {
			return *new(E), errs2.Wrap(err)
		}
	}
	return out, nil
}

// Fold applies the binary operation of the given operand type to all provided elements, returning the final result.
func Fold[S algebra.Operand[S]](first S, rest ...S) S {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc S, e S) S {
		return acc.Op(e)
	})
}

// Sum applies the addition operation of the given summand type to all provided elements, returning the final result.
func Sum[S algebra.Summand[S]](first S, rest ...S) S {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc S, e S) S {
		return acc.Add(e)
	})
}

// Prod applies the multiplication operation of the given multiplicand type to all provided elements, returning the final result.
func Prod[M algebra.Multiplicand[M]](first M, rest ...M) M {
	if len(rest) == 0 {
		return first
	}
	return iterutils.Reduce(slices.Values(rest), first, func(acc M, e M) M {
		return acc.Mul(e)
	})
}

// ScalarMul computes the scalar multiplication of the given base element by the given exponent using a fixed-window method.
func ScalarMul[E algebra.MonoidElement[E], S algebra.Numeric](base E, exponent S) E {
	monoid := algebra.StructureMustBeAs[algebra.Monoid[E]](base.Structure())

	precomputed := make([]E, 16)
	precomputed[0] = monoid.OpIdentity()
	precomputed[1] = base
	for i := 2; i < 16; i += 2 {
		precomputed[i] = precomputed[i/2].Op(precomputed[i/2])
		precomputed[i+1] = precomputed[i].Op(base)
	}

	res := monoid.OpIdentity()
	exponentBigEndianBytes := exponent.BytesBE()
	for _, si := range exponentBigEndianBytes {
		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		w := (si >> 4) & 0b1111
		res = res.Op(precomputed[w])

		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		res = res.Op(res)
		w = si & 0b1111
		res = res.Op(precomputed[w])
	}

	return res
}

// MultiScalarMul performs a Pippenger-style multi-scalar multiplication:
//
//	sum_i scalars[i] * points[i]
//
// using a fixed window size w.
//
// It assumes S.Bytes() is big-endian. Bits are extracted in LSB-first order.
func MultiScalarMul[E algebra.MonoidElement[E], S algebra.Numeric](
	scalars []S,
	points []E,
) E {
	n := len(points)
	if n == 0 {
		panic("MultiScalarMul: no points")
	}
	if n != len(scalars) {
		panic("MultiScalarMul: number of points and scalars must be equal")
	}

	monoid := algebra.StructureMustBeAs[algebra.Monoid[E]](points[0].Structure())

	// Use naive method for small n.
	if n <= 7 {
		acc := monoid.OpIdentity()
		for i := range n {
			acc = acc.Op(ScalarMul(points[i], scalars[i]))
		}
		return acc
	}

	// Precompute scalar bytes and max bit length.
	scalarBytes := make([][]byte, n)
	maxBits := 0
	for i, s := range scalars {
		b := s.BytesBE()
		scalarBytes[i] = b
		if bits := len(b) * 8; bits > maxBits {
			maxBits = bits
		}
	}
	if maxBits == 0 {
		// All scalars are zero.
		return monoid.OpIdentity()
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
	getWindow := func(b []byte, start int) uint {
		if len(b) == 0 {
			return 0
		}
		var acc uint = 0
		for k := 0; k < w; k++ {
			bitIndex := start + k
			byteCount := len(b)
			byteIndexFromLSB := bitIndex / 8
			if byteIndexFromLSB >= byteCount {
				break
			}
			byteIndex := byteCount - 1 - byteIndexFromLSB
			shift := uint(bitIndex % 8)
			bit := (b[byteIndex] >> shift) & 1
			acc |= uint(bit) << uint(k)
		}
		return acc
	}

	acc := monoid.OpIdentity()
	for wIdx := numWindows - 1; wIdx >= 0; wIdx-- {
		for i := 0; i < w; i++ {
			acc = acc.Op(acc)
		}
		buckets := make([]E, windowSize)
		for i := range buckets {
			buckets[i] = monoid.OpIdentity()
		}
		startBit := wIdx * w
		for i := range n {
			win := getWindow(scalarBytes[i], startBit)
			if win == 0 {
				continue
			}
			buckets[win] = buckets[win].Op(points[i])
		}

		// Summation by running sum from highest bucket down.
		// This gives: sum_{k=1}^{windowSize-1} k * bucket_k
		// with only ~windowSize additions.
		running := monoid.OpIdentity()
		for k := windowSize - 1; k > 0; k-- {
			if isIdentity := buckets[k].IsOpIdentity(); !isIdentity {
				running = running.Op(buckets[k])
			}
			acc = acc.Op(running)
		}
	}

	return acc
}

var ErrArgumentIsNil = errs2.New("argument is nil")
