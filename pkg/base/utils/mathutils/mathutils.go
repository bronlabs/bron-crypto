package mathutils

import (
	"encoding/binary"
	"io"
	"math/bits"

	"github.com/bronlabs/errs-go/errs"
)

// RandomUint64 samples a random uint64 from the provided PRNG.
func RandomUint64(prng io.Reader) (uint64, error) {
	var data [8]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0, errs.Wrap(err).WithMessage("failed to read random bytes")
	}

	return binary.LittleEndian.Uint64(data[:]), nil
}

// RandomUint64Range samples a random uint64 in the range [0, bound) from the provided PRNG.
func RandomUint64Range(prng io.Reader, bound uint64) (uint64, error) {
	// Rejection sampling: reject values in [0, threshold) where threshold = 2^64 % bound.
	// This ensures the remaining values are uniformly distributed across [0, bound).
	// The worst case is bound=2^63+1, for which the probability of rejection is ~1/2,
	// and the expected number of iterations before the loop terminates is 2.
	threshold := (-bound) % bound
	for {
		randBits, err := RandomUint64(prng)
		if err != nil {
			return 0, errs.Wrap(err).WithMessage("failed to sample random uint64")
		}
		if randBits >= threshold {
			return randBits % bound, nil
		}
	}
}

// CeilDiv returns `ceil(numerator/denominator) for integer inputs. Equivalently,
// it returns `x`, the smallest integer that satisfies `(x*b) >= a`.
func CeilDiv(numerator, denominator int) int {
	return (numerator - 1 + denominator) / denominator
}

// FloorLog2 return floor(log2(x)).
func FloorLog2(x int) int {
	return 63 - bits.LeadingZeros64(uint64(x))
}

// CeilLog2 return ceil(log2(x)).
func CeilLog2(x int) int {
	return 64 - bits.LeadingZeros64(uint64(x)-1)
}

// FactorialUint64 returns n! if a result does not overflow.
func FactorialUint64(n uint64) (uint64, error) {
	if n > 20 {
		return 0, errs.New("factorial overflow").WithStackFrame()
	}
	f := uint64(1)
	for i := uint64(2); i <= n; i++ {
		f *= i
	}
	return f, nil
}
