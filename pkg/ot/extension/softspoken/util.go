package softspoken

import (
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var (
	HashFn = base.TranscriptHashFunction
	dst    = []byte("Copper_Softspoken_COTe")
)

// HashSalted hashes the κ-bit length rows of a [LOTe*ξ][κ] bit matrix, outputs
// rows of κ bits in a [ξ][LOTe*κ] bit matrix. sessionId is used as a salt.
func HashSalted(sessionId []byte, bufferIn, bufferOut [][]byte) (err error) {
	Xi := len(bufferOut)
	LOTe := len(bufferIn) / Xi
	for j := 0; j < Xi; j++ {
		// Check lengths
		if len(bufferIn[j]) != KappaBytes {
			return errs.NewArgument("input slice bit-size is %d, should be %d", len(bufferIn[j]), KappaBytes)
		}
		if len(bufferOut[j]) != LOTe*KappaBytes {
			return errs.NewArgument("output slice bit-size is %d, should be %d", len(bufferOut[j]), LOTe*KappaBytes)
		}
		// Hash each element separately, same
		idx := []byte(strconv.Itoa(j))
		for l := 0; l < LOTe; l++ {
			digest, err := hashing.Hash(HashFn, dst, sessionId, idx, bufferIn[j*LOTe+l])
			if err != nil {
				return errs.WrapFailed(err, "writing into HashSalted")
			}
			copy(bufferOut[j][l*KappaBytes:(l+1)*KappaBytes], digest)
		}
	}
	return nil
}
