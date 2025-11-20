package mathutils

import (
	"encoding/binary"
	"io"
	"math/bits"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// RandomUint64 samples a random uint64 from the provided PRNG.
func RandomUint64(prng io.Reader) (uint64, error) {
	var data [8]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0, errs.WrapRandomSample(err, "cannot sample n")
	}

	return binary.LittleEndian.Uint64(data[:]), nil
}

// RandomUint64Range samples a random uint64 in the range [0, bound) from the provided PRNG.
func RandomUint64Range(prng io.Reader, bound uint64) (uint64, error) {
	// RandomUint64Range algorithm is slightly tricky. It rejects values that would result in an uneven distribution
	// (due to the fact that 2^64 is not divisible by n). The probability of a value being rejected depends on n.
	// The worst case is n=2^63+1, for which the probability of a reject is 1/2,
	// and the expected number of iterations before the loop terminates is 2.
	for {
		bits, err := RandomUint64(prng)
		if err != nil {
			return 0, errs.WrapRandomSample(err, "cannot sample n")
		}
		val := bits % bound
		if (bits - val) >= (bound - 1) {
			return val, nil
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
