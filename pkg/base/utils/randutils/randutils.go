package randutils

import (
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"io"
)

func RandomUint64(prng io.Reader) (uint64, error) {
	var data [8]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0, errs.WrapRandomSample(err, "cannot sample n")
	}

	return binary.LittleEndian.Uint64(data[:]), nil
}

// RandomUint64Range algorithm is slightly tricky. It rejects values that would result in an uneven distribution
// (due to the fact that 2^64 is not divisible by n). The probability of a value being rejected depends on n.
// The worst case is n=2^63+1, for which the probability of a reject is 1/2,
// and the expected number of iterations before the loop terminates is 2.
func RandomUint64Range(prng io.Reader, bound uint64) (uint64, error) {
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
